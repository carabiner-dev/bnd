// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/spf13/cobra"

	"github.com/carabiner-dev/bnd/pkg/render"
)

type readOptions struct {
	sigstoreOptions
	collectorOptions
	VerifySignatures bool
	DumpRaw          bool
}

// Validate checks the options
func (ro *readOptions) Validate() error {
	errs := []error{}
	errs = append(errs,
		ro.sigstoreOptions.Validate(),
		ro.collectorOptions.Validate(),
	)

	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (ro *readOptions) AddFlags(cmd *cobra.Command) {
	ro.sigstoreOptions.AddFlags(cmd)

	cmd.PersistentFlags().BoolVarP(
		&ro.VerifySignatures, "verify", "v", true, "verify the signatures of read attestations",
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
			for _, arg := range args {
				if !slices.Contains(opts.collectors, arg) {
					opts.collectors = append(opts.collectors, arg)
				}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// If there are no collectors, don't err. Just return the help screen
			if len(opts.collectors) == 0 {
				return cmd.Help()
			}
			if err := opts.Validate(); err != nil {
				return fmt.Errorf("validatging options: %w", err)
			}
			agent, err := opts.GetAgent()
			if err != nil {
				return fmt.Errorf("creating collector agent: %w", err)
			}

			atts, err := agent.Fetch(context.Background())
			if err != nil {
				return fmt.Errorf("fetching attestations: %w", err)
			}

			renderer, err := render.New(render.WithVerifySignatures(opts.VerifySignatures))
			if err != nil {
				return err
			}

			fmt.Println("\n🔎  Query Results:")
			fmt.Println("-----------------")
			for i, a := range atts {
				if opts.DumpRaw {
					fmt.Println(string(a.GetPredicate().GetData()))
					continue
				}

				fmt.Printf("\nAttestation #%d\n", i)
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
