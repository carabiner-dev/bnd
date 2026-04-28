// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"

	"github.com/carabiner-dev/signer"
	"github.com/carabiner-dev/signer/options"
	"github.com/spf13/cobra"
)

type verifyOptions struct {
	verifierSetOptions
	identityMatchOptions
	bundleOptions
}

// Validates the options in context with arguments
func (o *verifyOptions) Validate() error {
	return errors.Join(
		o.verifierSetOptions.Validate(),
		o.identityMatchOptions.Validate(),
		o.bundleOptions.Validate(),
	)
}

// AddFlags adds the flags to the subcommand
func (o *verifyOptions) AddFlags(cmd *cobra.Command) {
	o.verifierSetOptions.AddFlags(cmd)
	o.identityMatchOptions.AddFlags(cmd)
	o.bundleOptions.AddFlags(cmd)
}

// addVerify adds the verification command
func addVerify(parentCmd *cobra.Command) {
	opts := &verifyOptions{
		verifierSetOptions: defaultVerifierSetOptions(),
	}
	verifyCmd := &cobra.Command{
		Short:             "Verifies a bundle signature",
		Use:               "verify",
		Example:           fmt.Sprintf("%s verify bundle.json ", appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				if err := opts.SetBundlePath(args[0]); err != nil {
					return err
				}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}

			// Silence usage here as options are validated
			cmd.SilenceUsage = true

			verifier, err := signer.NewVerifierFromSet(opts.VerifierSet)
			if err != nil {
				return fmt.Errorf("building verifier: %w", err)
			}

			result, err := verifier.VerifyBundle(
				opts.Path,
				options.WithExpectedIdentity(opts.ExpectedIssuer, opts.ExpectedSan),
				options.WithExpectedIdentityRegex(opts.ExpectedIssuerRegex, opts.ExpectedSanRegex),
				options.WithSkipIdentityCheck(opts.SkipIdentityCheck),
			)
			if err != nil || result == nil {
				fmt.Println("\n❌ Bundle Verification Failed")
				fmt.Println("")
				if err != nil {
					return fmt.Errorf("error verifying bundle: %w", err)
				}
				return errors.New("bundle verify returned nil")
			}

			fmt.Printf("\n✅ Bundle Verification OK!\n")
			if !opts.SkipIdentityCheck && result.VerifiedIdentity != nil {
				fmt.Println("")
				san := result.VerifiedIdentity.SubjectAlternativeName.SubjectAlternativeName
				if san != "" {
					fmt.Printf("Signer:      %s\n", san)
				}
				// SPIFFE bundles have no OIDC issuer; only print when
				// we actually got one (sigstore path).
				if issuer := result.VerifiedIdentity.Issuer.Issuer; issuer != "" {
					fmt.Printf("OIDC Issuer: %s\n", issuer)
				}
			}
			fmt.Println("")

			return nil
		},
	}
	opts.AddFlags(verifyCmd)
	parentCmd.AddCommand(verifyCmd)
}
