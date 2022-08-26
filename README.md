# Basic sigstore rust signing implementation

[![Continuous integration](https://github.com/lukehinds/ferris-sign/actions/workflows/rust.yml/badge.svg)](https://github.com/lukehinds/ferris-sign/actions/workflows/rust.yml) | [![License: Apache 2.0](https://img.shields.io/badge/License-Apache2.0-brightgreen.svg)](https://opensource.org/licenses/Apache-2.0)

## Simple example flow

### Sign a file
Sign an example file, such as `README.md` from this directory:
```
cargo run -- --sign --cert-out cert.pem --in-file README.md --sig-out signature.bin
```

### View Fulcio signing certificate
View the Fulcio signing certificate produced with the `--sign` command:
```
openssl x509 -in cert.pem -text
```

### Extract public key
Extract the public key from the Fulcio signing certificate produced with the `--sign` command:
```
openssl x509 -pubkey -noout -in cert.pem > public.pem
```

### Verify the signature
Verify the signature, using the public key and the signature file produced with the `--sign` command:
```
openssl dgst -sha256 -verify public.pem -signature signature.bin README.md
```

You should then see:
```
 Verified OK
```
