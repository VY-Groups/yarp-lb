# Synthetic MaxMind MMDB fixtures

These two small databases are copied from MaxMind's official
[`MaxMind-DB/test-data`](https://github.com/maxmind/MaxMind-DB/tree/main/test-data)
directory. They are synthetic fixtures used only by cross-platform acceptance
tests; they are not production geolocation data. The upstream repository lists
Apache-2.0 and MIT licenses; its license texts are available in that repository.

| File | SHA-256 |
| --- | --- |
| `GeoIP2-Country-Test.mmdb` | `FC12D6470B35B70BD3E4534DD433D3E262A6C73F7682F85C344E832D4190F02B` |
| `GeoLite2-ASN-Test.mmdb` | `A0F9E8614AD582BA1AF3EEB18EAD666F73AD6E4CBD5280F80D5D4D95BBE6C3F1` |

Production database files are supplied by the operator under their own
MaxMind account and licensing terms. They are not committed or fetched by CI.
