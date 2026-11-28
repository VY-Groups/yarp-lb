"""Stage exact public VIP commissioning tools; never copy customer configuration."""
import argparse
import hashlib
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[2]
FILES = {
    "win-x64": {"ops/ha/Install-VipService.ps1": "ops/ha/Install-VipService.ps1"},
    "linux-x64": {"ops/ha/install-vip-service.sh": "ops/ha/install-vip-service.sh"},
}

def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def stage(root, rid, source=ROOT):
    if rid not in FILES:
        raise ValueError("unsupported VIP package platform")
    if not root.is_dir() or root.is_symlink():
        raise ValueError("existing ordinary candidate directory required")
    mapping = dict(FILES[rid])
    mapping["control-center/docs/ADC_DISTRIBUTED_VIP_ADMISSION.md"] = "ops/ha/ADC_DISTRIBUTED_VIP_ADMISSION.md"
    for src, dest in mapping.items():
        p = source / src
        if not p.is_file() or p.is_symlink():
            raise ValueError("missing or linked shipping commissioning input")
        if (root / dest).exists() or (root / dest).is_symlink():
            raise ValueError("refuse existing commissioning payload")
    target = root / "ops" / "ha"
    if target.exists() or target.is_symlink() or (root / "ops").is_symlink():
        raise ValueError("refuse existing or linked HA payload directory")
    target.mkdir(parents=True)
    try:
        for src, dest in mapping.items():
            shutil.copyfile(source / src, root / dest)
            if digest(source / src) != digest(root / dest):
                raise ValueError("shipping commissioning input changed")
        if rid == "linux-x64":
            (root / "ops/ha/install-vip-service.sh").chmod(0o755)
        if {p.relative_to(root).as_posix() for p in target.iterdir()} != set(mapping.values()):
            raise ValueError("unexpected HA payload")
    except Exception:
        shutil.rmtree(target)
        raise

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--rid", choices=FILES, required=True)
    args = parser.parse_args()
    stage(args.root, args.rid)
    print("PASS: exact public VIP commissioning payload staged without credentials or state")
