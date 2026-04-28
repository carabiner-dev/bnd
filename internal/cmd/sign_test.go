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
// initialized with the default signer-set (sigstore backend) parse the
// embedded sigstore roots and pass signer validation.
func TestSignerOptionsValidate(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		validate func() error
	}{
		{
			name: "statement",
			validate: func() error {
				opts := &statementOptions{signerSetOptions: defaultSignerSetOptions()}
				return opts.signerSetOptions.Validate()
			},
		},
		{
			name: "predicate",
			validate: func() error {
				opts := &predicateOptions{signerSetOptions: defaultSignerSetOptions()}
				return opts.signerSetOptions.Validate()
			},
		},
		{
			name: "commit",
			validate: func() error {
				opts := &commitOptions{signerSetOptions: defaultSignerSetOptions()}
				return opts.signerSetOptions.Validate()
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.NoError(t, tc.validate())
		})
	}
}

// TestSignerOptionsZeroValueFails verifies that a zero-valued
// signerSetOptions (without the default constructor) fails validation,
// confirming commands must be initialized via defaultSignerSetOptions().
func TestSignerOptionsZeroValueFails(t *testing.T) {
	t.Parallel()
	opts := signerSetOptions{}
	require.Error(t, opts.Validate())
}

// TestSignerOptionsSigstoreBackendBuilds verifies that the default
// signer set (no --signing-backend, no key/spiffe flags) auto-detects
// sigstore and produces an *options.Signer with the instance config
// needed to start a signing flow.
func TestSignerOptionsSigstoreBackendBuilds(t *testing.T) {
	t.Parallel()
	opts := defaultSignerSetOptions()
	require.Empty(t, opts.Backend, "Backend left empty so resolveBackend auto-detects")

	signerOpts, err := opts.BuildSigner()
	require.NoError(t, err)
	require.NotEmpty(t, signerOpts.OidcIssuerURL(), "OIDC issuer URL must be set after building signer options")
	require.NotEmpty(t, signerOpts.FulcioURL(), "Fulcio URL must be set after building signer options")
	require.NotNil(t, signerOpts.SigningConfig, "signing config must be set after building signer options")
}

// TestSignerCommandsRegisterFlags ensures the signing commands register
// flags from every backend (the bundled SignerSet exposes all of them
// in --help, with --backend selecting which one Validate/BuildSigner
// consults at runtime).
func TestSignerCommandsRegisterFlags(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		addFlags func(cmd *cobra.Command)
	}{
		{
			name: "statement",
			addFlags: func(cmd *cobra.Command) {
				opts := &statementOptions{signerSetOptions: defaultSignerSetOptions()}
				opts.AddFlags(cmd)
			},
		},
		{
			name: "predicate",
			addFlags: func(cmd *cobra.Command) {
				opts := &predicateOptions{signerSetOptions: defaultSignerSetOptions()}
				opts.AddFlags(cmd)
			},
		},
		{
			name: "commit",
			addFlags: func(cmd *cobra.Command) {
				opts := &commitOptions{signerSetOptions: defaultSignerSetOptions()}
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

			// The discriminator and at least one flag from each backend.
			for _, flag := range []string{
				"signing-backend",
				"signing-key",           // KeysSign
				"sigstore-roots",        // SigstoreCommon
				"sigstore-instance",     // SigstoreSign
				"sigstore-rekor-append", // SigstoreSign
				"sigstore-timestamp",    // SigstoreSign
				"sigstore-disable-sts",  // SigstoreSign
				"spiffe-trust-domain",   // SpiffeCommon
				"spiffe-socket",         // SpiffeSign
			} {
				require.NotNil(t, cmd.PersistentFlags().Lookup(flag), "flag %s must be registered", flag)
			}

			// OIDC flags are registered but hidden by defaultSignerSetOptions.
			oidc := cmd.PersistentFlags().Lookup("sigstore-oidc-client-id")
			require.NotNil(t, oidc, "sigstore-oidc-client-id must be registered")
			require.True(t, oidc.Hidden, "sigstore-oidc-client-id should be hidden in --help")

			require.NotNil(t, cmd.PersistentFlags().Lookup("sign"), "sign flag must be registered")
		})
	}
}

// TestSignerOptionsBackendSwitch verifies the --backend discriminator
// drives BuildSigner: switching to BackendKey produces a Signer
// configured for raw-key signing (no sigstore Instance plumbing).
func TestSignerOptionsBackendSwitch(t *testing.T) {
	t.Parallel()
	opts := defaultSignerSetOptions()
	opts.Backend = string(options.BackendKey)

	// BackendKey requires at least one key path; this is a flag-time
	// check, not a build-time check, so Validate passes.
	require.NoError(t, opts.Validate())

	// BuildSigner should fail because no signing key was supplied.
	_, err := opts.BuildSigner()
	require.Error(t, err)
	require.Contains(t, err.Error(), "no signing keys")
}
