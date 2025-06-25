// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/carabiner-dev/bnd/pkg/reader"
	"github.com/carabiner-dev/bnd/pkg/render"
)

type readOptions struct {
	sigstoreOptions
	BackendUri       string
	VerifySignatures bool
	DumpRaw          bool
}

// Validate checks the options
func (ro *readOptions) Validate() error {
	errs := []error{}
	errs = append(errs,
		ro.sigstoreOptions.Validate(),
	)

	if ro.BackendUri == "" {
		errs = append(errs, errors.New("missing source repository URI"))
	}
	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (ro *readOptions) AddFlags(cmd *cobra.Command) {
	ro.sigstoreOptions.AddFlags(cmd)

	cmd.PersistentFlags().StringVar(
		&ro.BackendUri, "uri", "", "source repository URI to read attestations",
	)

	cmd.PersistentFlags().BoolVarP(
		&ro.VerifySignatures, "verify", "v", true, "verify the attestation signatures",
	)
	cmd.PersistentFlags().BoolVar(
		&ro.DumpRaw, "raw", false, "dump the attestations in raw JSON",
	)
}

func addRead(parentCmd *cobra.Command) {
	opts := &readOptions{}
	readCmd := &cobra.Command{
		Short: "read attestations from source repositories",
		Long: fmt.Sprintf(`
🥨 %s read
The read subcommands lists attestations from a source repository. 

By using the read subcommand, bnd can retrieve attestations from different
repositories. Under the hood, this subcommand uses AMPEL's attestation
collector and its default drivers. Here are some use examples using different
repository drivers:

Read from a linear JSON file (jsonl):

> bnd read jsonl:attestations.jsonl

Read attestations from a git commit note:

> bnd read note:slsa-framework/slsa-source-poc@82d60d3569844fa1d060000909c6b62e3d3fd947 

Read from a GitHub release:

> bnd read release:github.com/example/repo@v1.0.1

Read from the GitHub attestations store:

> bnd read github:owner/repo

Read attestations from a directory:

> bnd read fs:/home/files/attestations/


`, appname),
		Use:               "read",
		Example:           fmt.Sprintf(`%s read source`, appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				opts.BackendUri = args[0]
			}
			return nil
		},
		RunE: func(_ *cobra.Command, args []string) error {
			client := reader.New()
			atts, err := client.Fetch(opts.BackendUri)
			if err != nil {
				return err
			}

			renderer, err := render.New(render.WithVerifySignatures(opts.VerifySignatures))
			if err != nil {
				return err
			}
			for _, a := range atts {
				if opts.DumpRaw {
					fmt.Println(string(a.GetPredicate().GetData()))
					continue
				}
				if err := renderer.DisplayEnvelopeDetails(os.Stdout, a); err != nil {
					return fmt.Errorf("rendering attestation: %w", err)
				}
			}
			return nil
		},
	}
	opts.AddFlags(readCmd)
	parentCmd.AddCommand(readCmd)
}
