// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bnd

import (
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

type VerifyCapable interface {
	Verify(verify.SignedEntity, verify.PolicyBuilder) (*verify.VerificationResult, error)
}

func NewVerifier() *Verifier {
	return &Verifier{
		Options:        DefaultVerifierOptions,
		bundleVerifier: &bundleVerifier{},
	}
}

type Verifier struct {
	Options        VerificationOptions
	bundleVerifier BundleVerifier
}

// VerifyBundle verifies a signed bundle containing a dsse envelope
func (v *Verifier) VerifyBundle(bundlePath string) (*verify.VerificationResult, error) {
	bndl, err := v.bundleVerifier.OpenBundle(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("opening bundle: %w", err)
	}

	vrfr, err := v.bundleVerifier.BuildSigstoreVerifier(&v.Options)
	if err != nil {
		return nil, fmt.Errorf("creating verifier: %w", err)
	}

	result, err := v.bundleVerifier.RunVerification(&v.Options, vrfr, bndl)
	if err != nil {
		return nil, fmt.Errorf("verifying bundle: %w", err)
	}

	return result, err
}

// VerifyBundle verifies a signed bundle containing a dsse envelope
func (v *Verifier) VerifyInlineBundle(bundleContents []byte) (*verify.VerificationResult, error) {
	var bndl bundle.Bundle

	err := bndl.UnmarshalJSON(bundleContents)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling JSON: %w", err)
	}
	return v.VerifyParsedBundle(&bndl)
}

func (v *Verifier) VerifyParsedBundle(bndl *bundle.Bundle) (*verify.VerificationResult, error) {
	vrfr, err := v.bundleVerifier.BuildSigstoreVerifier(&v.Options)
	if err != nil {
		return nil, fmt.Errorf("creating verifier: %w", err)
	}

	result, err := v.bundleVerifier.RunVerification(&v.Options, vrfr, bndl)
	if err != nil {
		return nil, fmt.Errorf("verifying bundle: %w", err)
	}

	return result, err
}
