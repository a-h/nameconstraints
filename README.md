## Tasks

### create-directory-structure

This directory structure is used to store the certificates and keys of the certificate authority.

```bash
mkdir -p ./ca/root ./ca/intermediate ./ca/certs
```

### create-root-key

Create a root key and cert with no restrictions.

```bash
mkdir -p ca/root ca/intermediate ca/certs

# Root key
openssl genrsa -out ca/root/root.key.pem 4096

# Root cert
openssl req -x509 -new -nodes -key ca/root/root.key.pem \
  -sha256 -days 3650 \
  -subj "/C=US/ST=Test/L=Test/O=RootCA/CN=Root CA" \
  -out ca/root/root.cert.pem
```

### create-intermediate-key

Create a key for the intermediate CA (the one that will be used to create client certs).

```bash
openssl genrsa -out ca/intermediate/intermediate.key.pem 4096

openssl req -new -key ca/intermediate/intermediate.key.pem \
  -subj "/C=US/ST=Test/L=Test/O=IntermediateCA/CN=Intermediate CA" \
  -out ca/intermediate/intermediate.csr.pem
```

### sign-intermediate-cert

Sign the intermediate cert with the root key, placing constraints on the intermediate cert that it can only be used to sign certs for the DNS entry only-this-domain-is-allowed.com and the `dirName` of `C=US/O=AllowedOrg`.

```bash
# Create the name constraints file.
cat > ca/intermediate/name_constraints.ext <<EOF
[ name_constraints ]
basicConstraints=CA:TRUE
keyUsage=keyCertSign, cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
nameConstraints = critical, permitted;DNS:only-this-domain-is-allowed.com, permitted;dirName:permitted_dn

[ permitted_dn ]
C=US
O=AllowedOrg
EOF
openssl x509 -req \
  -in ca/intermediate/intermediate.csr.pem \
  -CA ca/root/root.cert.pem -CAkey ca/root/root.key.pem -CAcreateserial \
  -out ca/intermediate/intermediate.cert.pem \
  -days 3650 -sha256 \
  -extfile ca/intermediate/name_constraints.ext \
  -extensions name_constraints
```

### create-certs

| Port | Domain         | Organisational Unit | Should Pass |
|------|----------------|---------------------|--------------|
| 8443 | Correct        | Correct             | Yes          |
| 8444 | Correct        | Incorrect           | No           |
| 8445 | Incorrect      | Correct             | No           |
| 8446 | Incorrect      | Incorrect           | No           |

The following commands create the certs for the test server. The `O=AllowedOrg` is the only one that is allowed to create certs for `only-this-domain-is-allowed.com`, so the other certs should be rejected.

```bash
# Create the certs for the test server.
# Domain correct, OU correct.
openssl genrsa -out ca/certs/domain_correct_ou_correct.key.pem 2048
openssl req -new -key ca/certs/domain_correct_ou_correct.key.pem \
  -subj "/C=US/O=AllowedOrg/CN=only-this-domain-is-allowed.com" \
  -out ca/certs/domain_correct_ou_correct.csr.pem
cat > ca/certs/domain_correct_ou_correct.ext <<EOF
subjectAltName = DNS:only-this-domain-is-allowed.com
EOF
openssl x509 -req \
  -in ca/certs/domain_correct_ou_correct.csr.pem \
  -CA ca/intermediate/intermediate.cert.pem \
  -CAkey ca/intermediate/intermediate.key.pem \
  -CAserial ca/intermediate/domain_correct_ou_correct.srl \
  -out ca/certs/domain_correct_ou_correct.cert.pem \
  -days 365 -sha256 \
  -extfile ca/certs/domain_correct_ou_correct.ext
# Domain correct, OU incorrect.
openssl genrsa -out ca/certs/domain_correct_ou_incorrect.key.pem 2048
openssl req -new -key ca/certs/domain_correct_ou_incorrect.key.pem \
  -subj "/C=US/O=WrongOrg/CN=only-this-domain-is-allowed.com" \
  -out ca/certs/domain_correct_ou_incorrect.csr.pem
cat > ca/certs/domain_correct_ou_incorrect.ext <<EOF
subjectAltName = DNS:only-this-domain-is-allowed.com
EOF
openssl x509 -req \
  -in ca/certs/domain_correct_ou_incorrect.csr.pem \
  -CA ca/intermediate/intermediate.cert.pem \
  -CAkey ca/intermediate/intermediate.key.pem \
  -CAserial ca/intermediate/domain_correct_ou_incorrect.srl \
  -out ca/certs/domain_correct_ou_incorrect.cert.pem \
  -days 365 -sha256 \
  -extfile ca/certs/domain_correct_ou_incorrect.ext
# Domain incorrect, OU correct.
openssl genrsa -out ca/certs/domain_incorrect_ou_correct.key.pem 2048
openssl req -new -key ca/certs/domain_incorrect_ou_correct.key.pem \
  -subj "/C=US/O=AllowedOrg/CN=this-domain-is-not-allowed.com" \
  -out ca/certs/domain_incorrect_ou_correct.csr.pem
cat > ca/certs/domain_incorrect_ou_correct.ext <<EOF
subjectAltName = DNS:this-domain-is-not-allowed.com
EOF
openssl x509 -req \
  -in ca/certs/domain_incorrect_ou_correct.csr.pem \
  -CA ca/intermediate/intermediate.cert.pem \
  -CAkey ca/intermediate/intermediate.key.pem \
  -CAserial ca/intermediate/domain_incorrect_ou_correct.srl \
  -out ca/certs/domain_incorrect_ou_correct.cert.pem \
  -days 365 -sha256 \
  -extfile ca/certs/domain_incorrect_ou_correct.ext
# Domain incorrect, OU incorrect.
openssl genrsa -out ca/certs/domain_incorrect_ou_incorrect.key.pem 2048
openssl req -new -key ca/certs/domain_incorrect_ou_incorrect.key.pem \
  -subj "/C=US/O=WrongOrg/CN=this-domain-is-not-allowed.com" \
  -out ca/certs/domain_incorrect_ou_incorrect.csr.pem
cat > ca/certs/domain_incorrect_ou_incorrect.ext <<EOF
subjectAltName = DNS:this-domain-is-not-allowed.com
EOF
openssl x509 -req \
  -in ca/certs/domain_incorrect_ou_incorrect.csr.pem \
  -CA ca/intermediate/intermediate.cert.pem \
  -CAkey ca/intermediate/intermediate.key.pem \
  -CAserial ca/intermediate/domain_incorrect_ou_incorrect.srl \
  -out ca/certs/domain_incorrect_ou_incorrect.cert.pem \
  -days 365 -sha256 \
  -extfile ca/certs/domain_incorrect_ou_incorrect.ext
```

### create-chains

To use the created certs in a web server for testing, the server needs to provide the full chain of trust, so the pem files are concatenated.

```bash
for name in domain_correct_ou_correct domain_correct_ou_incorrect domain_incorrect_ou_correct domain_incorrect_ou_incorrect; do cat ca/certs/$name.cert.pem ca/intermediate/intermediate.cert.pem > ca/certs/$name.chain.pem; done
```

### run-go-server

interactive: true

The test server runs endpoints at different ports for testing. This must be running before running the Go client.

```bash
go run ./server/main.go
```

### run-go-client

interactive: true

The test client connects to the Go server and validates that the certificates are accepted or rejected.

```bash
go run ./client/*.go
```

### run-python-client

interactive: true

The test client connects to the Go server and validates that the certificates are accepted or rejected.

```bash
python3 ./client-python/app.py
```

### run-node-client

interactive: true

The test client connects to the Go server and validates that the certificates are accepted or rejected.

```bash
node ./client-node/index.js
```

### run-dotnet-client

interactive: true

The test client connects to the Go server and validates that the certificates are accepted or rejected.

```bash
dotnet run --project ./ClientDotNet
```
