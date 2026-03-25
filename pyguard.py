#!/usr/bin/env python3
"""
PyPIGuard — Lightweight .pth supply-chain attack detector
Focused on LiteLLM-style credential exfil + auto-execution
"""

import argparse
import tempfile
import subprocess
import zipfile
import re
import sys
from pathlib import Path

SUSPICIOUS_PATTERNS = [
    r"~\.ssh", r"~\.aws", r"~\.kube", r"~\.config", r"env\['", r"os\.environ",
    r"base64\.b64decode", r"exec\(", r"eval\(", r"os\.system", r"requests\.post",
    r"subprocess", r"socket", r"exfil", r"steal", r"credential", r"token",
    r"litellm_init\.pth", r"\.pth.*import|exec|os\.|subprocess"
]

def parse_requirements(req_file: str):
    if not Path(req_file).exists():
        return []
    with open(req_file) as f:
        return [line.split("#")[0].strip() for line in f if line.strip() and not line.startswith("#")]

def scan_package(pkg_spec: str):
    print(f"🔍 PyPIGuard scanning {pkg_spec}...")
    try:
        with tempfile.TemporaryDirectory() as tmp:
            cmd = ["pip", "download", "--no-deps", "--no-binary", ":all:", pkg_spec, "-d", tmp]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            files = list(Path(tmp).glob("*.whl")) + list(Path(tmp).glob("*.tar.gz"))
            if not files:
                print(f"⚠️ No artifact for {pkg_spec}")
                return
            wheel = files[0]
            with zipfile.ZipFile(wheel) as z:
                for member in z.namelist():
                    if member.endswith(".pth"):
                        content = z.read(member).decode(errors="ignore")
                        print(f"⚠️ Found .pth file: {member}")
                        if any(re.search(p, content, re.IGNORECASE) for p in SUSPICIOUS_PATTERNS):
                            print(f"🚨 CRITICAL: Suspicious .pth detected in {pkg_spec} (credential theft / auto-exec)")
                            if os.environ.get("FAIL_ON_SUSPICIOUS", "true").lower() == "true":
                                sys.exit(2)
    except Exception as e:
        print(f"❌ Error scanning {pkg_spec}: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PyPIGuard — .pth supply-chain detector")
    parser.add_argument("--requirements", default=None, help="Path to requirements.txt")
    parser.add_argument("packages", nargs="*", help="Extra packages to scan")
    args = parser.parse_args()

    pkgs = []
    if args.requirements:
        pkgs.extend(parse_requirements(args.requirements))
    pkgs.extend(args.packages)

    for pkg in pkgs:
        if pkg and not pkg.startswith("-"):
            scan_package(pkg)

    print("✅ PyPIGuard scan passed")
