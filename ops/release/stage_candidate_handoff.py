"""Stage the public, exact-source offline operator handoff into a fresh candidate."""
import argparse
import posixpath
import re
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit
import shutil
from stage_vip_tools import ROOT, stage as stage_vip, digest, FILES

COMMON = {
    "ops/release/ISSUE48_CANDIDATE.md": "README.md",
    "control-center/docs/END_USER_SOP.md": "control-center/docs/END_USER_SOP.md",
    "control-center/docs/DATA_PROTECTION_PLATFORM_SUPPORT.md": "control-center/docs/DATA_PROTECTION_PLATFORM_SUPPORT.md",
    "ops/fleet/LINUX_DP_DISTRIBUTED_RUNTIME.md": "ops/fleet/LINUX_DP_DISTRIBUTED_RUNTIME.md",
}
# Explicit public allowlist: never recursively copy the checkout or follow
# arbitrary links to configuration, keys, credentials or customer state.
OPERATOR_REFERENCES = (
    "control-center/docs/OPERATOR_QUICK_GUIDE.md",
    "ops/windows-installer/README.md",
    "control-center/docs/ENTERPRISE_OIDC.md",
    "control-center/docs/LDAP_MAIL_SETUP.md",
    "control-center/docs/SIGNED_FLEET_CONFIG.md",
    "control-center/GatewayAgent/ENGINE_STAGING.md",
    "ops/waf/REMOTE_FENCED_NODE.md",
    "engines/GslbDns/README.md",
    "control-center/docs/OTEL_EXPORT.md",
    "control-center/docs/ONPREM_PRODUCTION_GO_GATES.md",
    # Transitive references and public CI definitions cited as evidence.
    "control-center/docs/MAIL_PROVIDER_SETUP.md",
    "engines/GslbDns/GSLB_FEATURE_STATUS.md",
    "control-center/docs/GSLB_BRANCH_DEEP_REVIEW.md",
    ".github/workflows/security-acceptance.yml",
    ".github/workflows/e2e-real-control-center.yml",
    ".github/workflows/smtp-starttls-e2e.yml",
)
COMMON.update({name:name for name in OPERATOR_REFERENCES})
HANDOFF_TOP_LEVEL = ("README.md","control-center","ops","engines",".github")
PLATFORM = {
    "win-x64": {},
    "linux-x64": {"ops/systemd/gatewaycore-yarp.service": "ops/systemd/gatewaycore-yarp.service"},
}

def mapping(rid):
    if rid not in PLATFORM:
        raise ValueError("unsupported handoff platform")
    return COMMON | PLATFORM[rid]

def handoff_paths(rid):
    return tuple(mapping(rid).values()) + tuple(FILES[rid].values()) + (
        "ops/ha/ADC_DISTRIBUTED_VIP_ADMISSION.md",)

# Inline and reference-definition destinations used in shipped Markdown.
# External evidence URLs are deliberately not fetched.
INLINE_LINK = re.compile(r"\]\(\s*(?:<([^>\r\n]+)>|([^\s()]+))(?:[ \t]+[\"'][^\r\n]*?[\"'])?\s*\)")
REFERENCE_LINK = re.compile(r"(?m)^[ \t]{0,3}\[[^\]\r\n]+\]:[ \t]*(?:<([^>\r\n]+)>|([^\s]+))")
FENCE = re.compile(r"^[ \t]{0,3}(\x60{3,}|~{3,})")

def markdown_targets(text):
    lines=[]
    fence=None
    for line in text.splitlines():
        match=FENCE.match(line)
        if match:
            marker=match.group(1)
            if fence is None:
                fence=marker
                continue
            if marker[0]==fence[0] and len(marker)>=len(fence) and not line[match.end():].strip():
                fence=None
                continue
        if fence is None:
            lines.append(line)
    body="\n".join(lines)
    for pattern in (INLINE_LINK,REFERENCE_LINK):
        for match in pattern.finditer(body):
            yield match.group(1) or match.group(2)

def verify_links(root, rid):
    """Check local file targets in all bundled Markdown, including referenced
    documents. Match exact filename case even on Windows."""
    count=0
    for name in handoff_paths(rid):
        if not name.endswith(".md"):
            continue
        document=root/name
        if not document.is_file() or document.is_symlink():
            raise ValueError("missing offline document: "+name)
        for target in markdown_targets(document.read_text(encoding="utf-8")):
            url=urlsplit(target)
            if url.scheme in ("http","https","mailto") or (url.netloc and not url.scheme):
                continue
            path=unquote(url.path)
            if url.scheme or "\\" in path or ":" in path or path.startswith("/"):
                raise ValueError("unsafe offline link in "+name+": "+target)
            if not path:
                continue
            relative=posixpath.normpath(posixpath.join(posixpath.dirname(name),path))
            if relative==".." or relative.startswith("../"):
                raise ValueError("offline link escapes package in "+name+": "+target)
            current=root
            for part in PurePosixPath(relative).parts:
                if not current.is_dir() or part not in {p.name for p in current.iterdir()}:
                    raise ValueError("unresolved offline link in "+name+": "+target)
                current=current/part
                if current.is_symlink():
                    raise ValueError("linked offline target in "+name+": "+target)
            if not current.is_file():
                raise ValueError("offline link is not a file in "+name+": "+target)
            count+=1
    return count

def stage(root, rid, source=ROOT):
    if not root.is_dir() or root.is_symlink():
        raise ValueError("existing ordinary candidate directory required")
    files=mapping(rid)
    # Fresh top-level destinations, never overlay an existing package tree.
    if any((root/name).exists() or (root/name).is_symlink()
           for name in HANDOFF_TOP_LEVEL):
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
        verify_links(root,rid)
    except Exception:
        for name in HANDOFF_TOP_LEVEL[1:]:
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
