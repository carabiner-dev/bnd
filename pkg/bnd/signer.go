// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bnd

import (
	"fmt"
	"io"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const GitHubTimeStamperURL = "https://timestamp.githubapp.com/api/v1/timestamp"

func NewSigner() *Signer {
	return &Signer{
		Options:      DefaultSignerOptions,
		bundleSigner: &bundleSigner{},
	}
}

type Signer struct {
	Options      SignerOptions
	bundleSigner BundleSigner
}

// WriteBundle writes the bundle JSON to
func (s *Signer) WriteBundle(bndl *v1.Bundle, w io.Writer) error {
	bundleJSON, err := protojson.Marshal(bndl)
	if err != nil {
		return fmt.Errorf("marshaling bundle: %w", err)
	}

	if _, err := w.Write(bundleJSON); err != nil {
		return fmt.Errorf("writing bundle: %w", err)
	}

	return nil
}

// SignStatement signs a statement using the configured options and
// returns a bundle. The signing process will try to obtain the
// signer identity in this order:
//
//  1. Try the configured ambient credentials providers
//     (currently only the GitHub actions plugin is supported).
//  2. If a terminal is detected, it will start the sigstore oidc
//     flow in a browser.
//  3. If no terminal is detected, it will start the sigstore device
//     flow.
func (s *Signer) SignStatement(data []byte) (*v1.Bundle, error) {
	// Verify the defined options:
	if err := s.Options.Validate(); err != nil {
		return nil, err
	}
	// check that statement is not empty and it is an intoto attestation
	if err := s.bundleSigner.VerifyContent(&s.Options, data); err != nil {
		return nil, fmt.Errorf("verifying content: %w", err)
	}

	// Wrap the attestation in its DSSE envelope
	content := s.bundleSigner.WrapStatement(data)

	// Get(or generate) the public key
	keypair, err := s.bundleSigner.GetKeyPair(&s.Options)
	if err != nil {
		return nil, err
	}

	// Run the STS providers to check for ambien credentials
	if err := s.bundleSigner.GetAmbienTokens(&s.Options); err != nil {
		return nil, fmt.Errorf("fetching ambient credentials: %w", err)
	}

	// Get the ID token
	if err := s.bundleSigner.GetOidcToken(&s.Options); err != nil {
		return nil, fmt.Errorf("getting ID token: %w", err)
	}

	// Generate the signer options
	bundleSignerOption, err := s.bundleSigner.BuildSigstoreSignerOptions(&s.Options)
	if err != nil {
		return nil, fmt.Errorf("building options: %w", err)
	}

	bndl, err := s.bundleSigner.SignBundle(content, keypair, bundleSignerOption)
	if err != nil {
		return nil, fmt.Errorf("singing statement: %w", err)
	}
	return bndl, nil
}
