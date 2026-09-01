"""palivane_detect - shared local detection for the at-rest scanners.

Both palivane-secrets and palivane-s3-scan detect HERE, on the machine that holds the
data, and send only metadata onward: what was found, where, and a masked preview. The
value itself never leaves. palivane-secrets has always worked this way; palivane-s3-scan
used to POST object text to the backend for scoring, which made Palivane a copy of
whatever sat in the bucket. That is the opposite of what this product is for, so
detection moved to the client and this is the shared copy so the two cannot drift.

Stdlib only, so it runs wherever the CLIs do. Served from /cli/palivane_detect.py and
installed beside them; either scanner will fetch it if it is missing.

  scan_text -> credentials and keys        (unchanged from palivane-secrets)
  scan_pii  -> personal and health data    (ported from the server's shadow_ai detector,
               so a client-side finding matches what the server would have said)
  scan_all  -> both, as (category, label, line, masked)

Nothing here returns a detected value. Anything that walks a filesystem or reads
permissions stays in palivane-secrets; a bucket scanner has no use for it.
"""
from __future__ import annotations

import math
import re
from collections import Counter

_STRIP = " (separator stripped — likely bypass)"
_PATTERNS = [
    ("Private key block", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("AWS access key id", re.compile(r"AKIA[0-9A-Z]{16}")),
    # The SECRET half. No distinguishing prefix — 40 chars of base64 — so it is gated on an
    # adjacent "secret[ access][ key]" label; ungated it would match any 40-char base64 run
    # (hashes, blob chunks). The entropy backstop below structurally cannot cover it:
    # _TOKEN_CANDIDATE_RE is [A-Za-z0-9_]{24,80}, and the "/" and "+" in a base64 secret
    # split those 40 chars into sub-24-char pieces, so every layer here missed it. Kept in
    # step with the server's patterns.py, where the same gap let a secret survive redaction.
    ("AWS secret access key",
     # (?<![A-Za-z0-9]) not \b: "_" is a word char, so \bsecret cannot match inside the
     # commonest spelling of all, aws_secret_access_key=…  The named group is the value, so
     # the masked preview is of the secret rather than of the label that gated it.
     re.compile(r"(?i)(?<![A-Za-z0-9])secret(?:[_ -]?access)?(?:[_ -]?key)?"
                r"\W{0,4}(?P<v>[A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("GitHub fine-grained PAT", re.compile(r"github_pat_[A-Za-z0-9_]{22,}")),
    ("GitLab PAT", re.compile(r"glpat-[A-Za-z0-9_\-]{20,}")),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{30,}")),
    ("Google OAuth token", re.compile(r"ya29\.[0-9A-Za-z_\-]{20,}")),
    ("OpenAI API key", re.compile(r"sk-[a-zA-Z0-9]{16,}")),
    # Modern OpenAI keys carry a dashed sub-marker (sk-proj-/sk-svcacct-/sk-admin-) that the
    # generic sk- above misses (the dash breaks its [a-zA-Z0-9] run).
    ("OpenAI API key", re.compile(r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}")),
    ("Anthropic API key", re.compile(r"sk-ant-[a-zA-Z0-9_\-]{16,}")),
    ("Stripe secret key", re.compile(r"\b[rs]k_(live|test)_[0-9a-zA-Z]{16,}")),
    ("npm token", re.compile(r"npm_[A-Za-z0-9]{36}")),
    ("PyPI token", re.compile(r"pypi-[A-Za-z0-9_\-]{16,}")),
    ("Slack webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}")),
    ("Slack app token", re.compile(r"xapp-[0-9]-[A-Za-z0-9-]{10,}")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}")),
    # More providers with distinctive, low-false-positive prefixes.
    ("SendGrid API key", re.compile(r"SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}")),
    ("Twilio API key SID", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("Square access token", re.compile(r"sq0(csp|atp)-[A-Za-z0-9_\-]{22,}")),
    ("Mailgun API key", re.compile(r"\bkey-[0-9a-f]{32}\b")),
    ("DigitalOcean token", re.compile(r"dop_v1_[a-f0-9]{64}")),
    ("Doppler token", re.compile(r"dp\.(?:pt|st|ct|sa|scim|audit)\.[A-Za-z0-9]{40,}")),
    ("HashiCorp Vault token", re.compile(r"\bhvs\.[A-Za-z0-9_\-]{24,}")),
    ("Grafana service account token", re.compile(r"glsa_[A-Za-z0-9]{32}_[0-9a-fA-F]{8}")),
    ("Terraform Cloud token", re.compile(r"[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-]{60,}")),
    ("Databricks token", re.compile(r"\bdapi[0-9a-f]{32}\b")),
    ("Notion integration token", re.compile(r"\bntn_[A-Za-z0-9]{40,}")),
    # evasion — separator stripped
    ("OpenAI API key" + _STRIP, re.compile(r"sk(proj|svcacct|admin)[A-Za-z0-9]{20,}")),
    ("Anthropic API key" + _STRIP, re.compile(r"skant[A-Za-z0-9]{16,}")),
    ("GitHub token" + _STRIP, re.compile(r"gh[pousr][A-Za-z0-9]{30,}")),
    ("GitHub fine-grained PAT" + _STRIP, re.compile(r"github_pat[A-Za-z0-9]{22,}")),
    ("GitLab PAT" + _STRIP, re.compile(r"glpat[A-Za-z0-9]{20,}")),
    ("Slack token" + _STRIP, re.compile(r"xox[baprs][A-Za-z0-9]{10,}")),
    ("Stripe secret key" + _STRIP, re.compile(r"\b[rs]k(live|test)[0-9a-zA-Z]{16,}")),
    ("npm token" + _STRIP, re.compile(r"npm[A-Za-z0-9]{36}")),
    ("PyPI token" + _STRIP, re.compile(r"pypi[A-Za-z0-9]{32,}")),
]
_ASSIGN_RE = re.compile(
    r"""(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|
        private[_-]?key|client[_-]?secret)\b\s*[:=]\s*['"]?([^\s'"]{8,})""", re.VERBOSE)

_CONN_RE = re.compile(
    r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|"
    r"clickhouse|cockroachdb|ftp)://[^\s:/@]+:([^\s:/@]{3,})@[^\s/]+", re.IGNORECASE)

_PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:x{3,}|\*{3,}|\.{3,}|changeme|change_me|placeholder|example|sample|dummy|fake|"
    r"redacted|your[_-]?\w+|my[_-]?\w+|test|password|passwd|pass|secret|token|<[^>]+>|"
    r"\$?\{[^}]+\}|\$[a-z_][a-z0-9_]*|%[a-z_]+%)$")

_ENTROPY_LABEL = "Possible secret (high-entropy token)"
_TOKEN_CANDIDATE_RE = re.compile(r"[A-Za-z0-9_]{24,80}")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_MIN_ENTROPY = 3.6


def _is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER_RE.match((value or "").strip()))


def _shannon_entropy(s: str) -> float:
    n = len(s)
    if n == 0:
        return 0.0
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _entropy_tokens(line: str) -> list[str]:
    """High-entropy token candidates in the *value* part of a line (after the first `=`/`:`,
    where a credential actually sits) — scoping to values keeps prose/code false positives low."""
    sep = min((i for i in (line.find("="), line.find(":")) if i >= 0), default=-1)
    if sep < 0:
        return []
    out = []
    for m in _TOKEN_CANDIDATE_RE.finditer(line[sep + 1:]):
        tok = m.group(0)
        if _HEX_RE.match(tok):
            continue
        classes = (any(c.islower() for c in tok) + any(c.isupper() for c in tok)
                   + any(c.isdigit() for c in tok))
        if classes >= 2 and _shannon_entropy(tok) >= _MIN_ENTROPY:
            out.append(tok)
    return out

def mask(secret: str) -> str:
    s = secret.strip()
    if len(s) <= 8:
        return "••••"
    return f"{s[:4]}••••{s[-4:]}"


def _line_secrets(line: str) -> list[tuple[str, str]]:
    """(label, raw value) for every credential on one line, in detection order: known-
    provider patterns, connection-URL credentials, labeled key=value assignments, and a
    tier-2 high-entropy heuristic for novel/vendor tokens with no recognized prefix.

    The single place the patterns are applied. scan_text() reports what this finds and
    redact() removes it, so a value one of them acts on can never be missed by the other."""
    out: list[tuple[str, str]] = []
    matched: set[str] = set()   # raw secrets found here — suppress entropy dupes
    for label, rx in _PATTERNS:
        m = rx.search(line)
        if not m:
            continue
        # A pattern that has to match surrounding context to identify its secret (the AWS
        # secret key's "secret_access_key" label) names the value group "v"; use that, so
        # neither the preview nor the redaction swallows the context along with it.
        val = m.groupdict().get("v") or m.group(0)
        matched.add(val)
        out.append((label, val))
    cm = _CONN_RE.search(line)
    if cm and not _is_placeholder(cm.group(1)):
        matched.add(cm.group(1))
        out.append(("Connection string credential", cm.group(1)))
    am = _ASSIGN_RE.search(line)
    if am and not _is_placeholder(am.group(1)):
        matched.add(am.group(1))
        out.append(("Credential assignment", am.group(1)))
    for tok in _entropy_tokens(line):
        # Don't re-flag a token a specific pattern already caught (as its type).
        if not any(tok in mv or mv in tok for mv in matched):
            out.append((_ENTROPY_LABEL, tok))
    return out


def scan_text(text: str) -> list[tuple[str, int, str]]:
    """Return (secret_type, line_no, masked_preview) for each credential in `text`.
    A repeat of the same value under the same label is reported once, at its first line."""
    found: list[tuple[str, int, str]] = []
    seen: set[tuple[str, str]] = set()
    for lineno, line in enumerate(text.splitlines(), 1):
        for label, val in _line_secrets(line[:4000]):
            if (label, val) not in seen:
                seen.add((label, val))
                found.append((label, lineno, mask(val)))
    return found


def redact(text: str) -> str:
    """`text` with every detected credential replaced by «redacted:label». For payloads
    that must be sent somewhere for analysis that does not need the value itself — an MCP
    config still shows which servers it declares and what they run once the tokens in its
    env block are gone.

    Every occurrence goes, not just the first: scan_text reports a repeated value once, but
    leaving the other copies in place would defeat the point. Longest values are replaced
    first so a short secret that happens to sit inside a longer one cannot leave a
    fragment of the longer one behind."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        for label, val in _line_secrets(line[:4000]):
            values.setdefault(val, label)
    for val in sorted(values, key=len, reverse=True):
        text = text.replace(val, f"\u00abredacted:{values[val]}\u00bb")
    return text


# --- document text extraction -------------------------------------------------------------
# A regulated record is more often a PDF or a spreadsheet than a typed sentence, and a
# scanner that only reads plain text reports those as clean. Stdlib only, so the same code
# runs in the at-rest scanners (which must not grow dependencies) and on the server.
#
# Deliberately narrow: this recovers text that is ALREADY text inside a container. It does
# not OCR (that needs Pillow + tesseract, and lives server-side) and it does not attempt
# encrypted PDFs or the pre-2007 binary Office formats. Anything it cannot read returns ""
# so the caller can report it as unread, which is the whole point — a scanner that silently
# skipped a file is indistinguishable from one that found nothing in it.

_OOXML_PARTS = {
    "docx": ("word/document.xml", "word/footnotes.xml", "word/endnotes.xml", "word/comments.xml"),
    "pptx": None,      # every ppt/slides/slideN.xml, plus notes
    "xlsx": None,      # xl/sharedStrings.xml carries the strings; sheets carry the numbers
}
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"[ \t]{2,}")
_MAX_EXTRACT_CHARS = 500_000


def _xml_text(blob: bytes) -> str:
    """Strip XML tags to their text. Paragraph and row ends become newlines first, so a
    spreadsheet column does not run into the next one and defeat the line-based scanners."""
    try:
        x = blob.decode("utf-8", errors="replace")
    except Exception:                                             # noqa: BLE001
        return ""
    x = re.sub(r"</(w:p|a:p|w:tr|row|si|c)>", "\n", x)
    x = _TAG_RE.sub(" ", x)
    for ent, ch in (("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"),
                    ("&quot;", '"'), ("&apos;", "'"), ("&#xa;", "\n")):
        x = x.replace(ent, ch)
    return _WS_RE.sub(" ", x)


def _extract_ooxml(data: bytes, kind: str) -> str:
    """docx / xlsx / pptx are ZIPs of XML, so no parser library is needed."""
    import io
    import zipfile
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:                                             # noqa: BLE001
        return ""
    names = zf.namelist()
    if kind == "docx":
        want = [n for n in _OOXML_PARTS["docx"] if n in names]
    elif kind == "pptx":
        want = sorted(n for n in names
                      if n.startswith(("ppt/slides/slide", "ppt/notesSlides/notesSlide"))
                      and n.endswith(".xml"))
    else:
        want = [n for n in names
                if n == "xl/sharedStrings.xml" or n.startswith("xl/worksheets/sheet")]
    out: list[str] = []
    for n in want:
        try:
            out.append(_xml_text(zf.read(n)))
        except Exception:                                         # noqa: BLE001
            continue
        if sum(len(p) for p in out) > _MAX_EXTRACT_CHARS:
            break
    return "\n".join(out)


_PDF_STREAM_RE = re.compile(rb"stream\r?\n(.*?)endstream", re.DOTALL)
_PDF_TJ_RE = re.compile(rb"\((?:\\.|[^\\()])*\)")


def _extract_pdf(data: bytes) -> str:
    """Text from an unencrypted PDF's content streams.

    PDF stores text as show-string operators inside (usually Flate-compressed) streams.
    Pulling the parenthesised literals gets the words without a font/layout engine: order
    is right, spacing is approximate. That is exactly enough for pattern detection and not
    enough to reconstruct the document, which is the right trade for a scanner.

    Encrypted PDFs and ones whose text is CID/Type0-encoded come back empty rather than as
    mojibake — garbage here would mean garbage findings."""
    import zlib
    chunks: list[str] = []
    for raw in _PDF_STREAM_RE.findall(data):
        body = raw
        try:
            # decompressobj, not decompress: a PDF stream is followed by an EOL before
            # "endstream", and the deflate payload itself may END in 0x0a or 0x0d. Stripping
            # those to remove the delimiter truncates one stream in roughly every few, and
            # the failure is silent — the file just extracts to nothing. decompressobj stops
            # at the end of the deflate data and ignores whatever trails it.
            body = zlib.decompressobj().decompress(raw)
        except Exception:                                         # noqa: BLE001
            pass                      # uncompressed stream, or a filter we do not handle
        if b"Tj" not in body and b"TJ" not in body:
            continue
        for lit in _PDF_TJ_RE.findall(body):
            t = lit[1:-1]
            t = (t.replace(b"\\(", b"(").replace(b"\\)", b")")
                  .replace(b"\\\\", b"\\").replace(b"\\n", b"\n").replace(b"\\t", b"\t"))
            chunks.append(t.decode("utf-8", errors="replace"))
        chunks.append("\n")
        if sum(len(c) for c in chunks) > _MAX_EXTRACT_CHARS:
            break
    text = "".join(chunks)
    # A CID-encoded or encrypted PDF yields bytes that decode to mostly control/replacement
    # characters. Report nothing rather than feed the detectors noise.
    printable = sum(1 for c in text if c.isprintable() or c in "\n\t")
    return text if text and printable / len(text) > 0.8 else ""


def extract_text(name: str, data: bytes) -> str:
    """Readable text from a file's bytes, or "" when the format needs something this cannot
    do (OCR, a PDF cipher, a pre-2007 Office binary). `name` supplies the extension."""
    ext = (name or "").rsplit(".", 1)[-1].lower() if "." in (name or "") else ""
    if not isinstance(data, (bytes, bytearray)) or not data:
        return ""
    data = bytes(data)
    if ext in ("docx", "docm", "xlsx", "xlsm", "pptx", "pptm"):
        return _extract_ooxml(data, {"docm": "docx", "xlsm": "xlsx",
                                     "pptm": "pptx"}.get(ext, ext))[:_MAX_EXTRACT_CHARS]
    if ext == "pdf" or data[:5] == b"%PDF-":
        return _extract_pdf(data)[:_MAX_EXTRACT_CHARS]
    try:                                    # plain text of any flavour
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return ""
    return text[:_MAX_EXTRACT_CHARS]


# --- PII / PHI ---------------------------------------------------------------------------
# Ported from the server's shadow_ai detector so a client-detected finding matches what the
# server would have said about the same bytes. The discipline there is worth keeping: a
# digit run is only reported when a check digit or a nearby keyword makes it self-
# identifying, because unqualified numeric matches are how PII detectors become noise
# nobody reads.

SSN_RE = re.compile(r"\b\d{3}[-\s]\d{2}[-\s]\d{4}\b")
SSN_NODASH_RE = re.compile(r"\b\d{9}\b")
SSN_CONTEXT_RE = re.compile(r"\b(ssn|social\s+security)\b", re.I)
PHONE_RE = re.compile(r"\b(?:\+?1[ .\-]?)?\(?\d{3}\)?[ .\-]\d{3}[ .\-]\d{4}\b")
CC_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]?){13,16}\b")
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[a-z]{2,}\b", re.IGNORECASE)

# Published sandbox PANs. They pass Luhn and appear in every payments tutorial, so they are
# suppressed only when the surrounding text is clearly illustrative; the same number in a
# transactional sentence still flags.
_TEST_CARDS = frozenset({
    "4111111111111111", "4012888888881881", "4222222222222", "4242424242424242",
    "4000056655665556", "5555555555554444", "5105105105105100", "5200828282828210",
    "2223003122003222", "378282246310005", "371449635398431", "378734493671000",
    "6011111111111117", "6011000990139424", "30569309025904", "38520000023237",
    "3530111333300000", "3566002020360505",
})
_TEST_CONTEXT_RE = re.compile(
    r"\b(test|testing|example|examples|e\.?g\.?|sample|sandbox|dummy|fake|placeholder|"
    r"such as|for instance|documentation|docs|tutorial|demo)\b", re.IGNORECASE)

# Self-identifying by format; safe without context.
_PII_STRONG = [
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b")),
    ("UK National Insurance no.", re.compile(r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]\b")),
]
# Ambiguous formats; only reported when a nearby keyword names the type.
_PII_CONTEXT = [
    ("passport number", re.compile(r"\bpassport\b", re.I), re.compile(r"\b[A-Z0-9]{6,9}\b")),
    ("employer ID (EIN)", re.compile(r"\b(ein|employer\s+id|tax\s+id)\b", re.I), re.compile(r"\b\d{2}-\d{7}\b")),
    ("bank routing number", re.compile(r"\b(routing|aba)\b", re.I), re.compile(r"\b\d{9}\b")),
    ("SWIFT/BIC", re.compile(r"\b(swift|bic)\b", re.I),
     re.compile(r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b")),
    ("Aadhaar", re.compile(r"\baadhaar\b", re.I), re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")),
]
# Health terms alongside a person make a record PHI rather than plain PII.
_PHI_CONTEXT_RE = re.compile(
    r"\b(diagnos\w*|patient|medical record|mrn|icd-?10|prescription|treatment|"
    r"health plan|insurance member|npi)\b", re.I)


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _valid_ssn9(d: str) -> bool:
    """SSA structural rules: area not 000/666 and not 900-999, group not 00, serial not 0000."""
    area, group, serial = d[:3], d[3:5], d[5:9]
    return area not in ("000", "666") and area[0] != "9" and group != "00" and serial != "0000"


def scan_pii(text: str) -> list[tuple[str, str, int, str]]:
    """(category, label, line_no, masked) for personal data. Category is pii_exposure, or
    phi_exposure when health context sits on the same line."""
    out: list[tuple[str, str, int, str]] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        cat = "phi_exposure" if _PHI_CONTEXT_RE.search(line) else "pii_exposure"
        seen: set[tuple[str, str]] = set()

        def add(label: str, value: str) -> None:
            k = (label, value)
            if k not in seen:
                seen.add(k)
                out.append((cat, label, lineno, mask(value)))

        for m in SSN_RE.finditer(line):
            if _valid_ssn9(re.sub(r"\D", "", m.group(0))):
                add("US Social Security number", m.group(0))
        if SSN_CONTEXT_RE.search(line):
            for m in SSN_NODASH_RE.finditer(line):
                if _valid_ssn9(m.group(0)):
                    add("US Social Security number", m.group(0))
        illustrative = bool(_TEST_CONTEXT_RE.search(line))
        for m in CC_CANDIDATE_RE.finditer(line):
            digits = re.sub(r"\D", "", m.group(0))
            if len(digits) < 13 or not _luhn_ok(digits):
                continue
            if digits in _TEST_CARDS and illustrative:
                continue
            add("payment card number", digits)
        for label, rx in _PII_STRONG:
            for m in rx.finditer(line):
                add(label, m.group(0))
        for label, ctx, rx in _PII_CONTEXT:
            if not ctx.search(line):
                continue
            for m in rx.finditer(line):
                add(label, m.group(0))
    return out


def scan_all(text: str) -> list[tuple[str, str, int, str]]:
    """Every finding in `text` as (category, label, line_no, masked). The only function the
    scanners call; nothing in the return value contains the detected value."""
    found = [("secret_leak", label, lineno, masked)
             for label, lineno, masked in scan_text(text)]
    found.extend(scan_pii(text))
    return found
