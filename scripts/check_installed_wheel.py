"""Check wheel contents and a clean installation outside the source checkout."""

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import venv
import zipfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path, nargs="?")
    args = parser.parse_args()
    candidates = [args.wheel] if args.wheel else list(Path("dist").glob("*.whl"))
    if len(candidates) != 1:
        parser.error("Specify one wheel explicitly, or place exactly one wheel in dist")
    wheel = candidates[0].resolve(strict=True)
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        for name in names:
            parts = Path(name).parts
            if any(p in {".git", ".aws", ".venv", "data", ".env"} for p in parts):
                raise ValueError("Private artifact in wheel")
            if name.endswith((".sqlite", ".db", ".log", ".jsonl")):
                raise ValueError("Operational evidence in wheel")
        assert "scry_security/rule_catalog/default.yaml" in names
        assert "scry_security/dashboard/index.html" in names
        assert "scry_security/dashboard/static/CHARTJS-LICENSE.md" in names
    with tempfile.TemporaryDirectory(prefix="scry-wheel-") as directory:
        root = Path(directory)
        environment = root / "venv"
        venv.EnvBuilder(with_pip=True).create(environment)
        python = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")

        def run(*arguments):
            subprocess.run([str(python), *arguments], cwd=root, check=True)

        run("-m", "pip", "install", "--upgrade", "pip")
        run("-m", "pip", "install", f"{wheel}[windows,packet-analysis]")
        run("-m", "pip", "check")
        run("-m", "scry_security", "--version")
        run("-m", "scry_security", "--check")
        run(
            "-c",
            "import importlib,pkgutil,scry_security; "
            "from importlib.resources import files; "
            "from scry_security.detection.loader import load_rules; "
            "assert 'site-packages' in str(scry_security.__file__); "
            "modules=[m.name for m in pkgutil.walk_packages(scry_security.__path__, "
            "scry_security.__name__+'.') if not m.name.endswith('.__main__')]; "
            "[importlib.import_module(m) for m in modules]; "
            "assert len(load_rules())==25; "
            "assert files('scry_security').joinpath('dashboard/static/app.js').is_file(); "
            "print('Installed library modules:',len(modules))",
        )
    print(
        json.dumps(
            {
                "wheel": wheel.name,
                "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
                "entries": len(names),
                "clean_install": "passed",
            }
        )
    )


if __name__ == "__main__":
    main()
