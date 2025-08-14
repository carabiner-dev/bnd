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
	sigstoreOptions
	verifcationOptions
	bundleOptions
}

// Validates the options in context with arguments
func (o *verifyOptions) Validate() error {
	return errors.Join(
		o.sigstoreOptions.Validate(),
		o.verifcationOptions.Validate(),
		o.bundleOptions.Validate(),
	)
}

// AddFlags adds the flags to the subcommand
func (o *verifyOptions) AddFlags(cmd *cobra.Command) {
	o.verifcationOptions.AddFlags(cmd)
	o.bundleOptions.AddFlags(cmd)
	o.sigstoreOptions.AddFlags(cmd)
}

// addVerify adds the verification command
func addVerify(parentCmd *cobra.Command) {
	opts := &verifyOptions{}
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

			verifier := signer.NewVerifier()
			verifier.Options = options.Verifier{
				RequireCTlog:        opts.RequireCTlog,
				RequireTimestamp:    opts.RequireTimestamp,
				RequireTlog:         opts.RequireTlog,
				ExpectedIssuer:      opts.ExpectedIssuer,
				ExpectedIssuerRegex: opts.ExpectedIssuerRegex,
				ExpectedSan:         opts.ExpectedSan,
				ExpectedSanRegex:    opts.ExpectedSanRegex,
				SkipIdentityCheck:   opts.SkipIdentityCheck,
			}
			verifier.Options.TufRootURL = opts.TufRootURL
			verifier.Options.TufRootPath = opts.TufRootPath
			result, err := verifier.VerifyBundle(opts.Path)
			if err != nil {
				fmt.Println("\n❌ Bundle Verification Failed")
				fmt.Println("")
				return fmt.Errorf("error verifying bundle: %w", err)
			}

			fmt.Printf("\n✅ Bundle Verification OK!\n")
			if !opts.SkipIdentityCheck {
				fmt.Println("")
				fmt.Printf("Signer:      %+s\n", result.VerifiedIdentity.SubjectAlternativeName.SubjectAlternativeName)
				fmt.Printf("OIDC Issuer: %+s\n", result.VerifiedIdentity.Issuer.Issuer)
			}
			fmt.Println("")
			return nil
		},
	}
	opts.AddFlags(verifyCmd)
	parentCmd.AddCommand(verifyCmd)
}
