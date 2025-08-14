// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/carabiner-dev/jsonl"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/helpers"
)

type packOptions struct {
	outFileOptions
	Bundles []string
}

// Validate the options in context with arguments
func (o *packOptions) Validate() error {
	errs := []error{}

	if o.OutPath != "" {
		if helpers.Exists(o.OutPath) {
			errs = append(errs, errors.New("specified output file already exists"))
		}
	}

	if len(o.Bundles) == 0 {
		errs = append(errs, errors.New("no bundles specified"))
	}
	return errors.Join(errs...)
}

func (o *packOptions) AddFlags(cmd *cobra.Command) {
	o.outFileOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringSliceVarP(
		&o.Bundles,
		"bundle", "b", []string{}, "path to bundle",
	)
}

func addPack(parentCmd *cobra.Command) {
	opts := packOptions{}
	packCmd := &cobra.Command{
		Short: "packs one or more bundles into a jsonl formatted file",
		Long: fmt.Sprintf(`
🥨 %s pack: Flatten and append bundles into a jsonl file.

The pack command reads individual bundle files, flattens the JSON data into
a single line and appends them to a jsonl file. This makes a number of
attestations easier to distribute.

`, appname),
		Use:           "pack [flags] bundle.json [bundle.json...]",
		SilenceUsage:  false,
		SilenceErrors: true,
		Example: fmt.Sprintf(`
Pack bundles and attestations together in a linear json file:

%s pack --bundle bundle1.json --bundle bundle2.json -o attestations.jsonl 

Same but with shortcut positional arguments:

%s pack -o attestations.jsonl bundle1.json bundle2.json 

If one of the --bundle paths is a directory, all JSON files found in the 
directory will be packed into the jsonl file: 

%s pack attestations-dir/ > attestations.jsonl 


`, appname, appname, appname),
		PersistentPreRunE: initLogging,
		PreRunE: func(_ *cobra.Command, args []string) error {
			opts.Bundles = append(opts.Bundles, args...)

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}

			cmd.SilenceUsage = true

			var out io.Writer
			out = os.Stdout
			defer func() {
				if f, ok := out.(*os.File); ok {
					f.Close() //nolint:errcheck,gosec
				}
			}()
			if opts.OutPath != "" {
				f, err := os.Create(opts.OutPath)
				if err != nil {
					return fmt.Errorf("creating jsonl file: %w", err)
				}
				out = f
			}

			return jsonl.PackFilesToStream(out, opts.Bundles)
		},
	}
	opts.AddFlags(packCmd)
	parentCmd.AddCommand(packCmd)
}
