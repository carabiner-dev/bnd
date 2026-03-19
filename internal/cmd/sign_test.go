// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"

	"github.com/carabiner-dev/signer/options"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

// TestSignerOptionsValidate verifies that the command options structs
// initialized with DefaultSigner can parse the embedded sigstore roots and
// pass signer validation. This ensures the signing commands can start the
// sigstore flow without errors like "OIDC issuer URL missing" or
// "signing config not set".
func TestSignerOptionsValidate(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		validate func() error
	}{
		{
			name: "statement",
			validate: func() error {
				opts := &statementOptions{Signer: options.DefaultSigner}
				return opts.Signer.Validate()
			},
		},
		{
			name: "predicate",
			validate: func() error {
				opts := &predicateOptions{Signer: options.DefaultSigner}
				return opts.Signer.Validate()
			},
		},
		{
			name: "commit",
			validate: func() error {
				opts := &commitOptions{Signer: options.DefaultSigner}
				return opts.Signer.Validate()
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.validate()
			require.NoError(t, err)
		})
	}
}

// TestSignerOptionsZeroValueFails verifies that a zero-valued Signer (without
// DefaultSigner) fails validation, confirming commands must be initialized
// with the default roots data.
func TestSignerOptionsZeroValueFails(t *testing.T) {
	t.Parallel()
	opts := options.Signer{}
	err := opts.Validate()
	require.Error(t, err)
}

// TestSignerOptionsRootsPopulated verifies that after parsing roots, the
// sigstore instance has the required signing configuration (OIDC issuer,
// Fulcio URL, etc.) needed to start a signing flow.
func TestSignerOptionsRootsPopulated(t *testing.T) {
	t.Parallel()
	signer := options.DefaultSigner
	require.NoError(t, signer.ParseRoots())

	require.NotEmpty(t, signer.OidcIssuerURL(), "OIDC issuer URL must be set after parsing roots")
	require.NotEmpty(t, signer.FulcioURL(), "Fulcio URL must be set after parsing roots")
	require.NotNil(t, signer.SigningConfig, "signing config must be set after parsing roots")
}

// TestSignerCommandsRegisterFlags ensures the signing commands register their
// flags without panicking and include the expected sigstore-prefixed flags.
func TestSignerCommandsRegisterFlags(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		addFlags func(cmd *cobra.Command)
	}{
		{
			name: "statement",
			addFlags: func(cmd *cobra.Command) {
				opts := &statementOptions{Signer: options.DefaultSigner}
				opts.AddFlags(cmd)
			},
		},
		{
			name: "predicate",
			addFlags: func(cmd *cobra.Command) {
				opts := &predicateOptions{Signer: options.DefaultSigner}
				opts.AddFlags(cmd)
			},
		},
		{
			name: "commit",
			addFlags: func(cmd *cobra.Command) {
				opts := &commitOptions{Signer: options.DefaultSigner}
				opts.AddFlags(cmd)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cmd := &cobra.Command{Use: "test"}
			require.NotPanics(t, func() {
				tc.addFlags(cmd)
			})
			// Verify the sigstore-prefixed OIDC flags are registered
			f := cmd.PersistentFlags().Lookup("sigstore-oidc-client-id")
			require.NotNil(t, f, "sigstore-oidc-client-id flag must be registered")

			// Verify the sign flag is registered
			f = cmd.PersistentFlags().Lookup("sign")
			require.NotNil(t, f, "sign flag must be registered")
		})
	}
}
