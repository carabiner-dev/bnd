// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/carabiner-dev/signer/options"
	"github.com/spf13/cobra"
)

type signOptions struct {
	Sign bool
}

func (so *signOptions) Validate() error {
	return nil
}

func (so *signOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVar(
		&so.Sign, "sign", true, "trigger the signing process",
	)
}

// signerSetOptions wraps the upstream options.SignerSet — the bundled
// sign-side OptionsSet that registers --backend plus every per-backend
// child set's flags (key, sigstore, spiffe). Use defaultSignerSetOptions
// to construct.
type signerSetOptions struct {
	*options.SignerSet
}

// defaultSignerSetOptions builds a signerSetOptions defaulted to the
// sigstore backend, matching the previous bnd default. The sigstore
// child's OIDC flags are hidden to keep --help compact; users who
// need to override OIDC details can still pass the hidden flags.
func defaultSignerSetOptions() signerSetOptions {
	set := options.DefaultSignerSet()
	if set.Sigstore != nil && set.Sigstore.Sign != nil {
		set.Sigstore.Sign.HideOIDCOptions = true
	}
	return signerSetOptions{SignerSet: set}
}
