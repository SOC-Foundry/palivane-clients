#!/usr/bin/env bash
# Package the extension into a zip for the Chrome Web Store / Edge Add-ons / self-hosting.
#
#   ./build.sh                                  # dev build (localhost defaults, as source)
#   PALIVANE_SAAS_URL=https://app.palivane.io ./build.sh   # PROD build for hosted SaaS:
#       - background.js  backendUrl + consoleUrl  -> the SaaS URL
#       - manifest host_permissions: drop localhost/127.0.0.1, add the SaaS origin
#   Source files are never modified; the prod transform happens in a temp staging copy.
set -euo pipefail
cd "$(dirname "$0")"

ver=$(grep -o '"version": *"[^"]*"' manifest.json | head -1 | sed 's/.*"\([0-9.]*\)"/\1/')
saas="${PALIVANE_SAAS_URL:-}"
suffix=""; [ -n "$saas" ] && suffix="-prod"
out="palivane-shadow-ai-guard-${ver}${suffix}.zip"
out_abs="$PWD/$out"
rm -f "$out"

files=(
  manifest.json managed_schema.json
  background.js content.js injected.js
  options.html options.js popup.html popup.js
)

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
cp "${files[@]}" "$stage"/
cp -r icons "$stage"/icons

if [ -n "$saas" ]; then
  echo "prod build -> $saas"
  python3 - "$stage" "$saas" <<'PY'
import json, re, sys
stage, saas = sys.argv[1], sys.argv[2].rstrip("/")
origin = saas + "/*"

# manifest: drop localhost hosts, ensure the SaaS origin is present.
mpath = f"{stage}/manifest.json"
m = json.load(open(mpath))
hp = [h for h in m.get("host_permissions", []) if "localhost" not in h and "127.0.0.1" not in h]
if origin not in hp:
    hp.append(origin)
m["host_permissions"] = hp
json.dump(m, open(mpath, "w"), indent=2)

# background.js: bake the SaaS URL as the default backend + console URL.
bpath = f"{stage}/background.js"
b = open(bpath).read()
b = re.sub(r'backendUrl:\s*"[^"]*"', f'backendUrl: "{saas}"', b, count=1)
b = re.sub(r'consoleUrl:\s*"[^"]*"', f'consoleUrl: "{saas}"', b, count=1)
open(bpath, "w").write(b)

# options.js: same default, so the Options form shows the SaaS URL pre-filled. Users
# never type it, installing the extension is enough; they just click "Sign in".
opath = f"{stage}/options.js"
o = open(opath).read()
o = re.sub(r'backendUrl:\s*"[^"]*"', f'backendUrl: "{saas}"', o, count=1)
open(opath, "w").write(o)
print("  manifest host_permissions:", hp)
PY
fi

if command -v zip >/dev/null 2>&1; then
  (cd "$stage" && zip -q -r "$out_abs" "${files[@]}" icons -x '*.DS_Store')
else
  python3 - "$stage" "$out_abs" "${files[@]}" <<'PY'
import sys, zipfile, os
stage, out, *files = sys.argv[1:]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for f in files:
        z.write(os.path.join(stage, f), f)
    for root, _, names in os.walk(os.path.join(stage, "icons")):
        for n in names:
            if n != ".DS_Store":
                full = os.path.join(root, n)
                z.write(full, os.path.relpath(full, stage))
PY
fi

echo "built $out"

if ! python3 -c "import zipfile,sys; sys.exit(0 if 'icons/icon-128.png' in zipfile.ZipFile('$out').namelist() else 1)"; then
  echo "ERROR: icons/icon-128.png missing from package. Chrome Web Store will reject it." >&2
  exit 1
fi

echo "Upload to the Chrome Web Store / Edge Add-ons (unlisted), or self-host the CRX."
echo "See STORE.md for the listing copy, privacy policy, and step-by-step submission."
