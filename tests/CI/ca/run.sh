#!/usr/bin/env bash
# Ephemeral synthetic CA ONLY; not issued by or connected to the organization's CA/HSM.
set -euo pipefail
repo=$(cd "$(dirname "$0")/../../.." && pwd)
mkdir -p "$repo/artifacts/ci-ca"
evidence="$repo/artifacts/ci-ca/results.txt"
lab=$(mktemp -d)
trap 'rm -rf "$lab"' EXIT
cd "$lab"
openssl req -new -x509 -nodes -newkey rsa:3072 -sha256 -days 2 -subj '/CN=Lab-01-Test-Root' -keyout ca.key -out ca.crt >/dev/null 2>&1
openssl req -new -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 -subj '/CN=Lab01-Service' -keyout leaf.key -out leaf.csr >/dev/null 2>&1
openssl x509 -req -in leaf.csr -CA ca.crt -CAkey ca.key -set_serial 0x1001 -days 2 -sha256 -out leaf.crt >/dev/null 2>&1
openssl req -new -nodes -newkey rsa:2048 -subj '/CN=Lab01-OCSP' -keyout responder.key -out responder.csr >/dev/null 2>&1
printf 'extendedKeyUsage=OCSPSigning\nkeyUsage=digitalSignature\n' > responder.ext
openssl x509 -req -in responder.csr -CA ca.crt -CAkey ca.key -set_serial 0x1002 -days 2 -sha256 -extfile responder.ext -out responder.crt >/dev/null 2>&1
exp=$(date -u -d "$(openssl x509 -in leaf.crt -enddate -noout | sed 's/notAfter=//')" '+%y%m%d%H%M%SZ')
printf 'V\t%s\t\t1001\tunknown\t/CN=Lab01-Service\n' "$exp" > index.txt
printf '1003\n' > serial
cat > ca.cnf <<EOC
[ca]
default_ca = CA_default
[CA_default]
database = $lab/index.txt
serial = $lab/serial
private_key = $lab/ca.key
certificate = $lab/ca.crt
default_md = sha256
default_crl_days = 1
EOC
openssl ca -gencrl -config ca.cnf -out crl.pem -batch >/dev/null 2>&1
openssl crl -in crl.pem -outform DER -out crl.der
openssl crl -in crl.der -inform DER -CAfile ca.crt -verify -noout >/dev/null
openssl verify -CAfile ca.crt -crl_check -CRLfile crl.pem leaf.crt | grep -q 'OK'
printf 'PASS: good certificate accepted by signed DER CRL\n' | tee -a "$evidence"
openssl ocsp -index index.txt -CA ca.crt -rsigner responder.crt -rkey responder.key -issuer ca.crt -cert leaf.crt -respout good.der -ndays 1 -no_nonce >/dev/null 2>&1
openssl ocsp -respin good.der -issuer ca.crt -cert leaf.crt -CAfile ca.crt -VAfile responder.crt -no_nonce -resp_text >good-check.log 2>&1
grep -q 'Response verify OK' good-check.log
grep -q 'leaf.crt: good' good-check.log
printf 'PASS: OCSP signed good status and chain verification\n' | tee -a "$evidence"
rev=$(date -u '+%y%m%d%H%M%SZ')
printf 'R\t%s\t%s\t1001\tunknown\t/CN=Lab01-Service\n' "$exp" "$rev" >index.txt
openssl ca -gencrl -config ca.cnf -out revoked-crl.pem -batch >/dev/null 2>&1
if openssl verify -CAfile ca.crt -crl_check -CRLfile revoked-crl.pem leaf.crt >crl-check.log 2>&1; then
  echo 'FAIL: revoked leaf accepted by CRL'; exit 1
fi
grep -q 'certificate revoked' crl-check.log
printf 'PASS: revoked leaf rejected using signed CRL\n' | tee -a "$evidence"
openssl ocsp -index index.txt -CA ca.crt -rsigner responder.crt -rkey responder.key -issuer ca.crt -cert leaf.crt -respout revoked.der -ndays 1 -no_nonce >/dev/null 2>&1
openssl ocsp -respin revoked.der -issuer ca.crt -cert leaf.crt -CAfile ca.crt -VAfile responder.crt -no_nonce -resp_text >revoked-check.log 2>&1
grep -q 'Response verify OK' revoked-check.log
grep -q 'leaf.crt: revoked' revoked-check.log
printf 'PASS: OCSP signed revoked status and chain verification\n' | tee -a "$evidence"
echo "CI SYNTHETIC CA PROTOCOL ACCEPTANCE PASSED (real CA not tested)" | tee -a "$evidence"
