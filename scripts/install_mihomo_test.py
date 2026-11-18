"""Download a pinned official test client; never installed into the VPS package."""
import gzip
import hashlib
import json
from pathlib import Path
import platform
import urllib.request

root=Path(__file__).resolve().parents[1]
pin=json.loads((root/'tests/mihomo-release.json').read_text())
machine={"x86_64":"amd64","amd64":"amd64","aarch64":"arm64","arm64":"arm64"}.get(platform.machine().lower())
assert machine, "unsupported test machine architecture"
asset=pin["assets"]["linux-"+machine]
url='https://github.com/MetaCubeX/mihomo/releases/download/'+pin['version']+'/'+asset['name']
with urllib.request.urlopen(url,timeout=120) as response: data=response.read(50_000_001)
assert len(data)<50_000_001 and hashlib.sha256(data).hexdigest()==asset['sha256']
dest=root/'tools/bin/mihomo';dest.parent.mkdir(parents=True,exist_ok=True)
dest.write_bytes(gzip.decompress(data));dest.chmod(0o755)
print('Pinned official Mihomo test client installed')
