// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/spf13/cobra"
)

const sigstoreFlagPrefix = "sigstore"

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
