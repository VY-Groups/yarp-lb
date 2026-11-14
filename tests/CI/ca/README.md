# 0.1 CA/PKI synthetic CI protocol fixture

Uses disposable OpenSSL-generated P-256 service leaf and RSA synthetic CA/OCSP responder; generates a DER CRL and signed OCSP responses. Verifies good and revoked cases and fails closed on incorrect outcomes. No internet, actual CA hostname, production certificate, HSM, issuance transaction, CCA/CPS or CAB approval is used. **Not a live CA acceptance test**.
