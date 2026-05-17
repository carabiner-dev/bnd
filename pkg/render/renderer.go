// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"strings"

	"github.com/carabiner-dev/attestation"
	ampelb "github.com/carabiner-dev/collector/envelope/bundle"
	signer "github.com/carabiner-dev/signer/api/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"

	"github.com/carabiner-dev/bnd/pkg/bundle"
)

func New(fn ...FnOpt) (*Renderer, error) {
	opts := defaultOptions
	for _, f := range fn {
		if err := f(&opts); err != nil {
			return nil, err
		}
	}
	return &Renderer{
		Options: opts,
	}, nil
}

type Renderer struct {
	Options Options
}

// unverifiedIdentityFromEnvelope reads the SAN/issuer straight from the bundle's
// cert so inspect can still show who signed when trust-chain verification fails.
func unverifiedIdentityFromEnvelope(envelope attestation.Envelope) (san, issuer string) {
	bndl, ok := envelope.(*ampelb.Envelope)
	if !ok {
		return "", ""
	}
	vm := bndl.GetVerificationMaterial()
	if vm == nil {
		return "", ""
	}
	var cert *protocommon.X509Certificate
	if c := vm.GetCertificate(); c != nil {
		cert = c
	} else if chain := vm.GetX509CertificateChain(); chain != nil && len(chain.GetCertificates()) > 0 {
		cert = chain.GetCertificates()[0]
	}
	if cert == nil {
		return "", ""
	}
	x509cert, err := parseDERorPEM(cert.GetRawBytes())
	if err != nil {
		return "", ""
	}
	summary, err := certificate.SummarizeCertificate(x509cert)
	if err != nil {
		return "", ""
	}
	return summary.SubjectAlternativeName, summary.Issuer
}

// parseDERorPEM accepts either DER (per the sigstore bundle spec) or PEM
// (seen in some non-conformant bundles in the wild).
func parseDERorPEM(raw []byte) (*x509.Certificate, error) {
	if cert, err := x509.ParseCertificate(raw); err == nil {
		return cert, nil
	}
	if block, _ := pem.Decode(raw); block != nil {
		return x509.ParseCertificate(block.Bytes)
	}
	return nil, fmt.Errorf("unable to parse certificate as DER or PEM")
}

// shortVerifyError trims the wrapped error chain to its first line.
func shortVerifyError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = msg[:i]
	}
	return strings.TrimSpace(msg)
}

// DisplayEnvelopeDetails prints the details of an attestation
func (r *Renderer) DisplayEnvelopeDetails(w io.Writer, envelope attestation.Envelope) error {
	tool := bundle.NewTool()

	att, err := tool.ExtractAttestation(envelope)
	if err != nil {
		return fmt.Errorf("unable to extract attestation from bundle")
	}

	mediatype := "unknown"
	if bndl, ok := envelope.(*ampelb.Envelope); ok {
		mediatype = bndl.GetMediaType()
	}

	fmt.Printf("✉️  Envelope Media Type: %s\n", mediatype)
	idstr := "[✗ not signed]\n"

	if r.Options.VerifySignatures {
		verifyErr := envelope.Verify(r.Options.PublicKeys)
		if verifyErr != nil {
			san, issuer := unverifiedIdentityFromEnvelope(envelope)
			switch {
			case san != "" && issuer != "":
				idstr = fmt.Sprintf("%s [⚠ unverified]\n%sIssuer: %s\n%s⚠ %s\n",
					san, strings.Repeat(" ", 20), issuer,
					strings.Repeat(" ", 20), shortVerifyError(verifyErr))
			case san != "":
				idstr = fmt.Sprintf("%s [⚠ unverified]\n%s⚠ %s\n",
					san, strings.Repeat(" ", 20), shortVerifyError(verifyErr))
			default:
				idstr = fmt.Sprintf("[⚠ unverified: %s]\n", shortVerifyError(verifyErr))
			}
		}
		if v := att.GetVerification(); v != nil {
			idstr = "[No identity found]\n"
			if v.GetVerified() {
				if sigv, ok := v.(*signer.Verification); ok {
					if sigv.GetSignature().GetIdentities() != nil {
						idstr = ""
						for i, id := range sigv.GetSignature().GetIdentities() {
							if i > 0 {
								idstr += strings.Repeat(" ", 19)
							}
							idstr += id.Principal() + "\n"
						}
					}
				}
			} else {
				idstr = "[✗ verification failed]\n"
			}
		}
	} else {
		idstr = "[not verified]\n"
	}
	fmt.Printf("🔏 Signer identity: %s", idstr)
	if att != nil {
		fmt.Println("📃 Attestation Details:")
		fmt.Printf("   Predicate Type: %s", att.GetPredicateType())
		if att.GetPredicateType() == "" {
			fmt.Print("[not defined]")
		}
		fmt.Println("")

		if att.GetSubjects() != nil {
			fmt.Printf("   Attestation Subjects:\n")
			for _, s := range att.GetSubjects() {
				if s.GetName() != "" {
					fmt.Println("   - " + s.GetName())
				}

				i := 0
				for algo, val := range s.GetDigest() {
					if i == 0 {
						if s.GetName() == "" {
							fmt.Print("   - ")
						} else {
							fmt.Print("     ")
						}
						fmt.Printf("%s: %s\n", algo, val)
					}
					i++
				}
			}
		} else {
			fmt.Println("⚠️ Attestation has no subjects")
		}
	} else {
		fmt.Println("⚠️ No attestation found in envelope")
	}
	fmt.Println("")
	return nil
}
