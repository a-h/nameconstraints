## Tasks

### create-directory-structure

```bash
mkdir -p ./ca/root ./ca/intermediate ./ca/certs
```

### create-root-key

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

```bash
openssl genrsa -out ca/intermediate/intermediate.key.pem 4096

openssl req -new -key ca/intermediate/intermediate.key.pem \
  -subj "/C=US/ST=Test/L=Test/O=IntermediateCA/CN=Intermediate CA" \
  -out ca/intermediate/intermediate.csr.pem
```

### sign-intermediate-cert

```bash
openssl x509 -req \
  -in ca/intermediate/intermediate.csr.pem \
  -CA ca/root/root.cert.pem -CAkey ca/root/root.key.pem -CAcreateserial \
  -out ca/intermediate/intermediate.cert.pem \
  -days 3650 -sha256 \
  -extfile ca/intermediate/name_constraints.ext
```

### create-valid-cert

The intermediate CA is allowed to create certs for only-this-domain-is-allowed.com

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

### create-invalid-cert

The intermediate CA can create certs for this-domain-is-not-allowed.com but they should be rejected by clients.

```bash
openssl genrsa -out ca/certs/not_allowed.key.pem 2048

openssl req -new -key ca/certs/not_allowed.key.pem \
  -subj "/CN=this-domain-is-not-allowed.com" \
  -out ca/certs/not_allowed.csr.pem

cat > ca/certs/not_allowed.ext <<EOF
subjectAltName = DNS:this-domain-is-not-allowed.com
EOF

openssl x509 -req \
  -in ca/certs/not_allowed.csr.pem \
  -CA ca/intermediate/intermediate.cert.pem \
  -CAkey ca/intermediate/intermediate.key.pem -CAcreateserial \
  -out ca/certs/not_allowed.cert.pem \
  -days 365 -sha256 \
  -extfile ca/certs/not_allowed.ext
```

### create-chains

The TLS server needs to send the intermediate cert along with the server cert.

```bash
cat ca/certs/not_allowed.cert.pem ca/intermediate/intermediate.cert.pem > ca/certs/not_allowed.chain.pem
cat ca/certs/allowed.cert.pem ca/intermediate/intermediate.cert.pem > ca/certs/allowed.chain.pem
```

### run-go-server

```bash
go run ./server/main.go
```

### run-go-client

```bash
go run ./client/main.go
```
