// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/command/keys"
	"github.com/carabiner-dev/jsonl"
	"github.com/spf13/cobra"

	"github.com/carabiner-dev/bnd/internal/supplychain"
	"github.com/carabiner-dev/bnd/pkg/bundle"
	"github.com/carabiner-dev/bnd/pkg/render"
)

type inspectOptions struct {
	keys.Options
	bundleOptions
	supplyChainOpts supplychain.Options
}

// Validates the options in context with arguments
func (o *inspectOptions) Validate() error {
	return errors.Join(
		o.Options.Validate(),
		o.bundleOptions.Validate(),
		o.supplyChainOpts.Validate(),
	)
}

func (o *inspectOptions) AddFlags(cmd *cobra.Command) {
	o.bundleOptions.AddFlags(cmd)
	o.Options.AddFlags(cmd)
	o.supplyChainOpts.AddFlags(cmd)
}

func addInspect(parentCmd *cobra.Command) {
	opts := inspectOptions{}
	extractCmd := &cobra.Command{
		Short: "prints useful information about a bundle",
		Long: fmt.Sprintf(`
🥨 %s inspect:  Inspect the contents of bundled attestations

This command is a work in progress. For now it just prints minimal
data about the bundle.

		`, appname),
		Use:               "inspect",
		Example:           fmt.Sprintf("%s inspect bundle.json ", appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 && opts.Path != "" && opts.Path != args[0] {
				return errors.New("bundle paths specified twice (as argument and flag)")
			}
			if len(args) > 0 {
				opts.Path = args[0]
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}

			cmd.SilenceUsage = true

			reader, closer, err := opts.OpenBundle()
			if err != nil {
				return fmt.Errorf("opening bundle: %w", err)
			}
			defer closer()

			// Merge supply chain keys
			if conf := opts.supplyChainOpts.GetSupplyChainConf(); conf != nil {
				scKeys, err := conf.GetPublicKeys()
				if err != nil {
					return fmt.Errorf("getting supply chain keys: %w", err)
				}
				opts.AddKeys(scKeys...)
			}

			keys, err := opts.ParseKeys()
			if err != nil {
				return err
			}

			fmt.Println("\n🔎  Bundle Details:")
			fmt.Println("-------------------")

			renderer, err := render.New(
				render.WithPublicKey(keys...),
			)
			if err != nil {
				return err
			}
			if strings.HasSuffix(opts.Path, ".jsonl") {
				for i, r := range jsonl.IterateBundle(reader) {
					if r == nil {
						fmt.Printf("Unable to parse line #%d\n", i)
						continue
					}
					fmt.Printf("Attestation #%d\n", i)
					if err := printEnvelopeDetails(renderer, r); err != nil {
						return err
					}
				}
				return nil
			}

			// If it's just a single json:
			return printEnvelopeDetails(renderer, reader)
		},
	}
	opts.AddFlags(extractCmd)
	parentCmd.AddCommand(extractCmd)
}

func printEnvelopeDetails(renderer *render.Renderer, reader io.Reader) error {
	tool := bundle.NewTool()

	// Parse the bundle JSON
	envelope, err := tool.ParseBundle(reader)
	if err != nil {
		if errors.Is(err, attestation.ErrNotCorrectFormat) {
			fmt.Printf("⚠️  JSON data is not a known envelope format\n\n")
			return nil
		}
		return fmt.Errorf("parsing bundle: %w", err)
	}
	return renderer.DisplayEnvelopeDetails(os.Stdout, envelope)
}
