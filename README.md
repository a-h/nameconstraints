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
openssl x509 -req \
  -in ca/intermediate/intermediate.csr.pem \
  -CA ca/root/root.cert.pem -CAkey ca/root/root.key.pem -CAcreateserial \
  -out ca/intermediate/intermediate.cert.pem \
  -days 3650 -sha256 \
  -extfile ca/intermediate/name_constraints.ext \
  -extensions name_constraints
```

### create-valid-cert

The intermediate CA is allowed to create certs for only-this-domain-is-allowed.com - this matches the DNS constraint.

```bash
openssl genrsa -out ca/certs/allowed.key.pem 2048

openssl req -new -key ca/certs/allowed.key.pem \
  -subj "/CN=only-this-domain-is-allowed.com" \
  -out ca/certs/allowed.csr.pem

cat > ca/certs/allowed.ext <<EOF
subjectAltName = DNS:only-this-domain-is-allowed.com
EOF

openssl x509 -req \
  -in ca/certs/allowed.csr.pem \
  -CA ca/intermediate/intermediate.cert.pem \
  -CAkey ca/intermediate/intermediate.key.pem -CAcreateserial \
  -out ca/certs/allowed.cert.pem \
  -days 365 -sha256 \
  -extfile ca/certs/allowed.ext
```

### create-invalid-cert-correct-domain-wrong-o

With this cert, note that the `subj` is `/C=US/O=WrongOrg/CN=only-this-domain-is-allowed.com` - i.e. the `O=WrongOrg` which is not permitted. So, even though the DNS constraint is OK (DNS:only-this-domain-isallowed.com`), clients should reject this cert, because the `dirName` is set to `WrongOrg`, not `AllowedOrg`.

```bash
openssl genrsa -out ca/certs/correct_domain_wrong_o.key.pem 2048

openssl req -new -key ca/certs/correct_domain_wrong_o.key.pem \
  -subj "/C=US/O=WrongOrg/CN=only-this-domain-is-allowed.com" \
  -out ca/certs/correct_domain_wrong_o.csr.pem

cat > ca/certs/correct_domain_wrong_o.ext <<EOF
subjectAltName = DNS:only-this-domain-is-allowed.com
EOF

openssl x509 -req \
  -in ca/certs/correct_domain_wrong_o.csr.pem \
  -CA ca/intermediate/intermediate.cert.pem \
  -CAkey ca/intermediate/intermediate.key.pem -CAcreateserial \
  -out ca/certs/correct_domain_wrong_o.cert.pem \
  -days 365 -sha256 \
  -extfile ca/certs/correct_domain_wrong_o.ext
```

### create-invalid-cert-incorrect-domain-correct-o

In this case, the domain is not allowed, but the `O=AllowedOrg`, so again, clients should reject, because the DNS constraint does not match.

```bash
openssl genrsa -out ca/certs/incorrect_domain_correct_o.key.pem 2048

openssl req -new -key ca/certs/incorrect_domain_correct_o.key.pem \
  -subj "/C=US/O=AllowedOrg/CN=this-domain-is-not-allowed.com" \
  -out ca/certs/incorrect_domain_correct_o.csr.pem

cat > ca/certs/incorrect_domain_correct_o.ext <<EOF
subjectAltName = DNS:this-domain-is-not-allowed.com
EOF

openssl x509 -req \
  -in ca/certs/incorrect_domain_correct_o.csr.pem \
  -CA ca/intermediate/intermediate.cert.pem \
  -CAkey ca/intermediate/intermediate.key.pem -CAcreateserial \
  -out ca/certs/incorrect_domain_correct_o.cert.pem \
  -days 365 -sha256 \
  -extfile ca/certs/incorrect_domain_correct_o.ext
```

### create-chains

To use the created certs in a web server for testing, the server needs to provide the full chain of trust, so the pem files are concatenated.

```bash
cat ca/certs/allowed.cert.pem ca/intermediate/intermediate.cert.pem > ca/certs/allowed.chain.pem
cat ca/certs/correct_domain_wrong_o.cert.pem ca/intermediate/intermediate.cert.pem > ca/certs/correct_domain_wrong_o.chain.pem
cat ca/certs/incorrect_domain_correct_o.cert.pem ca/intermediate/intermediate.cert.pem > ca/certs/incorrect_domain_correct_o.chain.pem
```

### run-go-server

The test server runs endpoints at different ports for testing. This must be running before running the Go client.

```bash
go run ./server/main.go
```

### run-go-client

The test client connects to the Go server and validates that the certificates are accepted or rejected.

```bash
go run ./client/main.go
```
