// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"

	"github.com/carabiner-dev/signer/options"
	"github.com/spf13/cobra"
)

// verifierSetOptions wraps options.VerifierSet — the bundled
// verify-side OptionsSet. It registers --key (raw public-key
// verification), --sigstore-roots, and the --spiffe-* namespace; the
// verifier dispatches to the right backend by inspecting the bundle's
// leaf certificate (SPIFFE leaf carries a spiffe:// URI SAN). Callers
// supply trust material for whichever backends they're willing to
// accept; the inactive children contribute nothing at validate time.
type verifierSetOptions struct {
	*options.VerifierSet
}

func defaultVerifierSetOptions() verifierSetOptions {
	return verifierSetOptions{VerifierSet: options.DefaultVerifierSet()}
}

// identityMatchOptions covers the sigstore-style certificate-identity
// assertions that aren't part of the OptionsSet families. SPIFFE
// identity constraints (trust domain, path) flow through
// --spiffe-trust-domain / --spiffe-path / --spiffe-path-regex on the
// VerifierSet, so they're not duplicated here.
type identityMatchOptions struct {
	SkipIdentityCheck   bool
	ExpectedIssuer      string
	ExpectedIssuerRegex string
	ExpectedSan         string
	ExpectedSanRegex    string
}

func (o *identityMatchOptions) AddFlags(cmd *cobra.Command) {
	pf := cmd.PersistentFlags()
	pf.BoolVar(&o.SkipIdentityCheck, "skip-identity", false,
		"allow skipping identity verification")
	pf.StringVar(&o.ExpectedSan, "identity", "",
		"expected sigstore certificate identity (SAN)")
	pf.StringVar(&o.ExpectedSanRegex, "identity-regex", "",
		"regex to check the sigstore certificate identity (SAN)")
	pf.StringVar(&o.ExpectedIssuer, "issuer", "",
		"expected OIDC issuer for the certificate identity")
	pf.StringVar(&o.ExpectedIssuerRegex, "issuer-regex", "",
		"regex to check the certificate's OIDC identity issuer")
}

func (o *identityMatchOptions) Validate() error {
	var errs []error
	if o.ExpectedIssuer != "" && o.ExpectedIssuerRegex != "" {
		errs = append(errs, errors.New("only one of --issuer or --issuer-regex can be set"))
	}
	if o.ExpectedSan != "" && o.ExpectedSanRegex != "" {
		errs = append(errs, errors.New("only one of --identity or --identity-regex can be set"))
	}
	return errors.Join(errs...)
}
