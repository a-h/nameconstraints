package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

// NameConstraints mirrors the ASN.1 structure from RFC 5280.
type NameConstraints struct {
	Permitted []GeneralSubtree `asn1:"tag:0,optional"`
	Excluded  []GeneralSubtree `asn1:"tag:1,optional"`
}

// GeneralSubtree holds a Base (GeneralName) plus optional min/max.
type GeneralSubtree struct {
	Base    asn1.RawValue
	Minimum int `asn1:"tag:0,optional,default:0"`
	Maximum int `asn1:"tag:1,optional"`
}

// CertVerifier holds a root CA pool for chain validation.
type CertVerifier struct {
	RootPool *x509.CertPool
}

// NewCertVerifier returns a basic verifier with the given root pool.
func NewCertVerifier(rootPool *x509.CertPool) *CertVerifier {
	return &CertVerifier{RootPool: rootPool}
}

// VerifyPeerCertificate is used in a TLS-like handshake to verify certs manually.
func (cv *CertVerifier) VerifyPeerCertificate(serverName string) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("no certificates provided")
		}

		// Parse all raw certs.
		certs := make([]*x509.Certificate, len(rawCerts))
		for i, raw := range rawCerts {
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				return fmt.Errorf("failed to parse certificate %d: %w", i, err)
			}
			certs[i] = cert
		}

		// Create an intermediate pool.
		intermediatePool := x509.NewCertPool()
		for _, cert := range certs[1:] {
			intermediatePool.AddCert(cert)
		}

		// Remove NameConstraints from unhandled critical extensions because
		// they're not supported by the standard library, but this code supports
		// them manually.
		for _, cert := range certs {
			var unhandled []asn1.ObjectIdentifier
			for _, ext := range cert.UnhandledCriticalExtensions {
				if ext.Equal([]int{2, 5, 29, 30}) {
					continue
				}
				unhandled = append(unhandled, ext)
			}
			cert.UnhandledCriticalExtensions = unhandled
		}

		// Standard chain verification.
		opts := x509.VerifyOptions{
			Intermediates: intermediatePool,
			Roots:         cv.RootPool,
			DNSName:       serverName,
		}
		chains, err := certs[0].Verify(opts)
		if err != nil {
			return fmt.Errorf("failed to verify certificate: %w", err)
		}

		// Hostname check.
		if err := verifyHostname(certs[0], serverName); err != nil {
			return err
		}

		// Manually enforce the directoryName constraints in each issuer.
		for _, chain := range chains {
			for _, issuer := range chain[1:] {
				if err := enforceDirNameConstraints(issuer, certs[0]); err != nil {
					return err
				}
			}
		}

		return nil
	}
}

// verifyHostname checks if the leaf certificate has the serverName in DNSNames.
func verifyHostname(leaf *x509.Certificate, serverName string) error {
	for _, dnsName := range leaf.DNSNames {
		if dnsName == serverName {
			return nil
		}
	}
	return fmt.Errorf("leaf certificate does not contain hostname %q", serverName)
}

// enforceDirNameConstraints checks directoryName and DNS constraints.
func enforceDirNameConstraints(issuer, leaf *x509.Certificate) error {
	var nc *NameConstraints
	for _, ext := range issuer.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 30}) {
			var err error
			nc, err = parseNameConstraints(ext)
			if err != nil {
				return fmt.Errorf("failed to parse NameConstraints: %w", err)
			}
		}
	}
	if nc == nil {
		return nil
	}

	// Handle directoryName constraints.
	permittedDirNames := directoryNamesFromSubtrees(nc.Permitted)
	excludedDirNames := directoryNamesFromSubtrees(nc.Excluded)

	// Reject if leaf matches any excluded dirName.
	for _, d := range excludedDirNames {
		if subjectsMatch(leaf.Subject, d) {
			return fmt.Errorf("subject %v is excluded by dirName constraint %v", leaf.Subject, d)
		}
	}

	// If there are permitted dirNames, the leaf must match at least one.
	if len(permittedDirNames) > 0 {
		ok := false
		for _, d := range permittedDirNames {
			if subjectsMatch(d, leaf.Subject) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("subject %v does not match any of the permitted dirName constraints: %v", leaf.Subject, permittedDirNames)
		}
	}

	// Handle DNS constraints.
	permittedDomains := domainNamesFromSubtrees(nc.Permitted)
	excludedDomains := domainNamesFromSubtrees(nc.Excluded)

	// Check each DNS name in the leaf.
	for _, dnsName := range leaf.DNSNames {
		// Exclusion check.
		for _, ed := range excludedDomains {
			if ed == dnsName {
				return fmt.Errorf("DNS name %q is excluded by name constraints", dnsName)
			}
		}
		// If there are permitted domains, must match at least one of them.
		if len(permittedDomains) > 0 {
			inPermitted := false
			for _, pd := range permittedDomains {
				if pd == dnsName {
					inPermitted = true
					break
				}
			}
			if !inPermitted {
				return fmt.Errorf("DNS name %q not in permitted domains", dnsName)
			}
		}
	}
	return nil
}

// parseNameConstraints unmarshals a DER-encoded NameConstraints extension.
func parseNameConstraints(ext pkix.Extension) (*NameConstraints, error) {
	var nc NameConstraints
	rest, err := asn1.Unmarshal(ext.Value, &nc)
	if err != nil {
		return nil, fmt.Errorf("unmarshal NameConstraints: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("trailing data after NameConstraints")
	}
	return &nc, nil
}

// directoryNamesFromSubtrees returns directoryName constraints as pkix.Name.
func directoryNamesFromSubtrees(subtrees []GeneralSubtree) []pkix.Name {
	var out []pkix.Name
	for _, st := range subtrees {
		if st.Base.Tag == 4 { // directoryName
			name, err := parseDirectoryName(st.Base)
			if err != nil {
				fmt.Printf("warning: could not parse dirName subtree: %v\n", err)
				continue
			}
			out = append(out, name)
		}
	}
	return out
}

// parseDirectoryName handles EXPLICIT [4] Name (SEQUENCE of RDNs).
func parseDirectoryName(raw asn1.RawValue) (pkix.Name, error) {
	var wrapper asn1.RawValue
	if _, err := asn1.Unmarshal(raw.FullBytes, &wrapper); err != nil {
		return pkix.Name{}, fmt.Errorf("failed to unmarshal directoryName wrapper: %v", err)
	}

	var rdnSeq pkix.RDNSequence
	if _, err := asn1.Unmarshal(wrapper.Bytes, &rdnSeq); err != nil {
		return pkix.Name{}, fmt.Errorf("failed to unmarshal RDNSequence: %v", err)
	}

	var name pkix.Name
	name.FillFromRDNSequence(&rdnSeq)
	return name, nil
}

// domainNamesFromSubtrees returns DNSName strings in the subtrees (tag=2).
func domainNamesFromSubtrees(subtrees []GeneralSubtree) []string {
	var out []string
	for _, st := range subtrees {
		if st.Base.Tag == 2 {
			out = append(out, string(st.Base.Bytes))
		}
	}
	return out
}

// isSubtreeMatch returns true if 'subject' is within the 'permitted' subtree.
// That means subject's RDNs must start with permitted's RDNs in order.
func subjectsMatch(permitted, subject pkix.Name) bool {
	pRDNs := permitted.ToRDNSequence()
	sRDNs := subject.ToRDNSequence()
	if len(pRDNs) > len(sRDNs) {
		return false
	}
	for i := range pRDNs {
		if !rdnEqual(pRDNs[i], sRDNs[i]) {
			return false
		}
	}
	return true
}

func rdnEqual(a, b pkix.RelativeDistinguishedNameSET) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Type.Equal(b[i].Type) || a[i].Value != b[i].Value {
			return false
		}
	}
	return true
}
