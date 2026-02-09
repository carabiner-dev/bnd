// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/carabiner-dev/attestation"
	ampelb "github.com/carabiner-dev/collector/envelope/bundle"

	"github.com/carabiner-dev/bnd/pkg/bundle"
	signer "github.com/carabiner-dev/signer/api/v1"
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
			idstr = fmt.Sprintf("[verification error: %s]\n", verifyErr)
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
							idstr += id.Slug() + "\n"
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
