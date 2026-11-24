#!/usr/bin/env python3
"""Offline, recipient-specific encrypted Linux DP wrapping-key delivery.

The signer and recipient pins, intended wrapping identity and exact revision
are independently approved, never learned from the incoming envelope.
OpenSSL CMS provides authenticated encryption and an outer signature.
No network service, automatic activation, or key-ring snapshot is included.
"""
import argparse
import base64
import contextlib
import datetime
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import linux_dp_mtls_transport as wire

OPENSSL = "/usr/bin/openssl"
MAX_PFX = 1024 * 1024
MAX_WIRE = 2 * 1024 * 1024
MAX_CERT = 65536
ID = re.compile(r"[a-z0-9][a-z0-9_-]{1,47}\Z", re.ASCII)


def b64(value):
    return base64.b64encode(value).decode("ascii")


def digest(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def openssl(args, data=b"", fds=(), cap=MAX_WIRE):
    result = subprocess.run([OPENSSL, *args], input=data,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20,
        pass_fds=tuple(fds), check=False, env={"PATH":"/usr/bin:/bin","LC_ALL":"C"})
    if result.returncode or len(result.stdout)>cap:
        raise ValueError("bounded cryptographic operation refused")
    return result.stdout


@contextlib.contextmanager
def memory_files(*values):
    # Inherited anonymous descriptors prevent secret copies to temp files,
    # environment variables, command-line arguments or captured stderr.
    fds=[]
    try:
        for value in values:
            fd=os.memfd_create("gatewaycore-offline-credential",os.MFD_CLOEXEC)
            fds.append(fd)
            with os.fdopen(os.dup(fd),"wb") as stream:
                stream.write(value)
                stream.flush()
            os.lseek(fd,0,os.SEEK_SET)
        yield fds, ["/proc/self/fd/"+str(fd) for fd in fds]
    finally:
        for fd in fds:
            os.close(fd)


def json_bytes(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),
                      ensure_ascii=True,allow_nan=False).encode("ascii")


def strict_json(raw):
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:
                raise ValueError("duplicate credential envelope field")
            result[key]=value
        return result
    return json.loads(raw.decode("ascii"),object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def metadata(fleet,recipient,revision,signer_pin,recipient_pin,wrapping_pin):
    if (type(fleet) is not str or not ID.fullmatch(fleet) or
            type(recipient) is not str or not ID.fullmatch(recipient) or
            type(revision) is not int or not 1<=revision<=2**63-1):
        raise ValueError("invalid independently approved delivery identity")
    pins=[wire.pin(x) for x in (signer_pin,recipient_pin,wrapping_pin)]
    if len(set(pins))!=3:
        raise ValueError("signing, recipient and wrapping identities must differ")
    return {"schemaVersion":1,"kind":"linux-dp-wrap-delivery",
            "fleet":fleet,"recipient":recipient,"revision":revision,
            "signerSha256":pins[0],"recipientSha256":pins[1],
            "wrappingSha256":pins[2]}


def approved_cert(raw, pin, usage):
    der=openssl(["x509","-outform","DER"],raw,cap=MAX_CERT)
    if not hmac.compare_digest(digest(der),pin):
        raise ValueError("certificate differs from independently approved pin")
    extensions=openssl(["x509","-noout","-ext","basicConstraints,keyUsage"],raw,cap=8192)
    if b"CA:FALSE" not in extensions or usage not in extensions:
        raise ValueError("unapproved credential certificate purpose")
    dates=openssl(["x509","-noout","-dates"],raw,cap=1024).decode("ascii").splitlines()
    if len(dates)!=2 or not dates[0].startswith("notBefore=") or not dates[1].startswith("notAfter="):
        raise ValueError("unapproved certificate validity")
    parsed=[datetime.datetime.strptime(v.split("=",1)[1],"%b %d %H:%M:%S %Y GMT")
            .replace(tzinfo=datetime.timezone.utc) for v in dates]
    now=datetime.datetime.now(datetime.timezone.utc)
    if not parsed[0]<=now<parsed[1]:
        raise ValueError("expired or inactive delivery identity")
    return der


def password_bytes(raw):
    value=raw.rstrip(b"\r\n")
    if not 1<=len(value)<=512 or any(c<33 or c>126 for c in value):
        raise ValueError("wrapping password must be bounded printable ASCII")
    return value


def validate_pfx(pfx,password,wrapping_pin):
    if type(pfx) is not bytes or not 1<=len(pfx)<=MAX_PFX:
        raise ValueError("unbounded wrapping PFX")
    with memory_files(pfx,password+b"\n") as (fds,paths):
        cert=openssl(["pkcs12","-in",paths[0],"-passin","fd:"+str(fds[1]),
                     "-clcerts","-nokeys"],fds=fds,cap=MAX_CERT)
        if cert.count(b"-----BEGIN CERTIFICATE-----")!=1:
            raise ValueError("exactly one wrapping leaf required")
    approved_cert(cert,wrapping_pin,b"Key Encipherment")
    with memory_files(pfx,password+b"\n") as (fds,paths):
        key=openssl(["pkcs12","-in",paths[0],"-passin","fd:"+str(fds[1]),
                    "-nocerts","-nodes"],fds=fds,cap=MAX_CERT)
    # Check that a real private key matches the leaf. Do not rely on
    # PKCS#12 bag labels or accept a certificate-only bundle.
    public_cert=openssl(["x509","-pubkey","-noout"],cert,cap=MAX_CERT)
    cert_spki=openssl(["pkey","-pubin","-outform","DER"],public_cert,cap=MAX_CERT)
    key_spki=openssl(["pkey","-pubout","-outform","DER"],key,cap=MAX_CERT)
    if not hmac.compare_digest(cert_spki,key_spki):
        raise ValueError("wrapping PFX private key does not match approved certificate")


def seal(approved,pfx,password,signer_cert,signer_key,recipient_cert):
    password=password_bytes(password)
    validate_pfx(pfx,password,approved["wrappingSha256"])
    approved_cert(signer_cert,approved["signerSha256"],b"Digital Signature")
    approved_cert(recipient_cert,approved["recipientSha256"],b"Key Encipherment")
    payload=json_bytes(dict(approved,pfx=b64(pfx),password=b64(password)))
    with memory_files(recipient_cert) as (fds,paths):
        encrypted=openssl(["cms","-encrypt","-binary","-outform","DER",
            "-aes-256-gcm","-recip",paths[0],"-keyopt","rsa_padding_mode:oaep",
            "-keyopt","rsa_oaep_md:sha256","-keyopt","rsa_mgf1_md:sha256"],
            payload,fds)
    with memory_files(signer_cert,signer_key) as (fds,paths):
        signed=openssl(["cms","-sign","-binary","-nodetach","-nosmimecap",
            "-md","sha256","-signer",paths[0],"-inkey",paths[1],
            "-passin","pass:","-outform","DER"],encrypted,fds)
    return signed


def open_envelope(approved,envelope,signer_cert,recipient_cert,recipient_key):
    if type(envelope) is not bytes or not 0<len(envelope)<=MAX_WIRE:
        raise ValueError("unbounded wrapping envelope")
    approved_cert(signer_cert,approved["signerSha256"],b"Digital Signature")
    approved_cert(recipient_cert,approved["recipientSha256"],b"Key Encipherment")
    # No trust in embedded signer certs. The exact preapproved leaf was
    # validated above; -noverify skips chain discovery, NOT signature checks.
    with memory_files(signer_cert) as (fds,paths):
        encrypted=openssl(["cms","-verify","-binary","-inform","DER",
            "-nointern","-certfile",paths[0],"-noverify"],envelope,fds)
    with memory_files(recipient_cert,recipient_key) as (fds,paths):
        plaintext=openssl(["cms","-decrypt","-binary","-inform","DER",
            "-recip",paths[0],"-inkey",paths[1],"-passin","pass:"],encrypted,fds)
    doc=strict_json(plaintext)
    if (type(doc) is not dict or set(doc)!=set(approved)|{"pfx","password"} or
            any(type(doc[k]) is not type(v) or doc[k]!=v for k,v in approved.items())):
        raise ValueError("signed envelope not for this approved node/revision")
    pfx=base64.b64decode(doc["pfx"],validate=True)
    password=password_bytes(base64.b64decode(doc["password"],validate=True))
    validate_pfx(pfx,password,approved["wrappingSha256"])
    return pfx,password


def publish(root,approved,entries):
    root_fd=wire.private_directory(root)
    try:
        label=approved["fleet"]+"--"+approved["recipient"]+"--"+str(approved["revision"])
        final=os.path.join(root,label)
        if os.path.lexists(final):
            raise ValueError("credential revision already published")
        staging=tempfile.mkdtemp(prefix=".dp-wrap-",dir=root)
        try:
            os.chmod(staging,0o700)
            for name,data in entries.items():
                if name not in ("envelope.der","wrapper.pfx","wrapper.password","receipt.json"):
                    raise ValueError("invalid delivery output")
                wire.safe_write(os.path.join(staging,name),data)
            fd=os.open(staging,wire.O_DIR)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            wire.publish_no_replace(staging,final)
            os.fsync(root_fd)
            return final
        finally:
            if os.path.lexists(staging):
                shutil.rmtree(staging)
    finally:
        os.close(root_fd)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command",choices=("seal","open"))
    for name in ("fleet","recipient","signer-certificate","signer-sha256",
                 "recipient-certificate","recipient-sha256","wrapping-sha256","output-root"):
        parser.add_argument("--"+name,required=True)
    parser.add_argument("--revision",type=int,required=True)
    for name in ("signer-key","recipient-key","pfx","password-file","envelope"):
        parser.add_argument("--"+name)
    args=parser.parse_args(argv)
    try:
        approval=metadata(args.fleet,args.recipient,args.revision,
            args.signer_sha256,args.recipient_sha256,args.wrapping_sha256)
        signer=wire.read_private_path(args.signer_certificate,MAX_CERT)
        recipient=wire.read_private_path(args.recipient_certificate,MAX_CERT)
        if args.command=="seal":
            if not all((args.signer_key,args.pfx,args.password_file)) or args.recipient_key or args.envelope:
                raise ValueError("invalid seal inputs")
            envelope=seal(approval,wire.read_private_path(args.pfx,MAX_PFX),
                wire.read_private_path(args.password_file,1024),signer,
                wire.read_private_path(args.signer_key,MAX_CERT),recipient)
            publish(args.output_root,approval,{"envelope.der":envelope,
                "receipt.json":json_bytes(dict(approval,envelopeSha256=digest(envelope)))})
        else:
            if not all((args.recipient_key,args.envelope)) or any((args.signer_key,args.pfx,args.password_file)):
                raise ValueError("invalid open inputs")
            envelope=wire.read_private_path(args.envelope,MAX_WIRE)
            pfx,password=open_envelope(approval,envelope,signer,recipient,
                wire.read_private_path(args.recipient_key,MAX_CERT))
            publish(args.output_root,approval,{"wrapper.pfx":pfx,
                "wrapper.password":password+b"\n",
                "receipt.json":json_bytes(dict(approval,envelopeSha256=digest(envelope)))})
        print("PASS: approved offline wrapping-key delivery")
        return 0
    except (OSError,ValueError,TypeError,KeyError,subprocess.SubprocessError):
        print("REFUSED: wrapping-key delivery failed closed")
        return 1


if __name__=="__main__":
    raise SystemExit(main())
