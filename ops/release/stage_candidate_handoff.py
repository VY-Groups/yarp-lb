"""Stage the public, exact-source offline operator handoff into a fresh candidate."""
import argparse
from pathlib import Path
import shutil
from stage_vip_tools import ROOT, stage as stage_vip, digest, FILES

COMMON = {
    "ops/release/ISSUE48_CANDIDATE.md": "README.md",
    "control-center/docs/END_USER_SOP.md": "control-center/docs/END_USER_SOP.md",
    "control-center/docs/DATA_PROTECTION_PLATFORM_SUPPORT.md": "control-center/docs/DATA_PROTECTION_PLATFORM_SUPPORT.md",
    "ops/fleet/LINUX_DP_DISTRIBUTED_RUNTIME.md": "ops/fleet/LINUX_DP_DISTRIBUTED_RUNTIME.md",
}
PLATFORM = {
    "win-x64": {"ops/windows-installer/README.md": "ops/windows-installer/README.md"},
    "linux-x64": {"ops/systemd/gatewaycore-yarp.service": "ops/systemd/gatewaycore-yarp.service"},
}

def mapping(rid):
    if rid not in PLATFORM:
        raise ValueError("unsupported handoff platform")
    return COMMON | PLATFORM[rid]

def handoff_paths(rid):
    return tuple(mapping(rid).values()) + tuple(FILES[rid].values()) + (
        "ops/ha/ADC_DISTRIBUTED_VIP_ADMISSION.md",)

def stage(root, rid, source=ROOT):
    if not root.is_dir() or root.is_symlink():
        raise ValueError("existing ordinary candidate directory required")
    files=mapping(rid)
    # Fresh top-level destinations, never overlay an existing package tree.
    if any((root/name).exists() or (root/name).is_symlink()
           for name in ("README.md","control-center","ops")):
        raise ValueError("existing or linked handoff payload")
    for src in files:
        p=source/src
        if not p.is_file() or p.is_symlink():
            raise ValueError("missing or linked handoff source")
    try:
        for src,dest in files.items():
            target=root/dest
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(source/src,target)
            if digest(source/src)!=digest(target):
                raise ValueError("handoff source changed")
        stage_vip(root,rid,source)
        if any(not (root/name).is_file() for name in handoff_paths(rid)):
            raise ValueError("incomplete offline handoff")
    except Exception:
        for name in ("control-center","ops"):
            path=root/name
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
        (root/"README.md").unlink(missing_ok=True)
        raise

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--root",type=Path,required=True)
    parser.add_argument("--rid",choices=PLATFORM,required=True)
    args=parser.parse_args()
    stage(args.root,args.rid)
    print("PASS: exact public platform documentation and VIP commissioning tools staged")
