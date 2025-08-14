// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"

	"github.com/carabiner-dev/jsonl"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/helpers"
)

type unpackOptions struct {
	archivePath     string // Path to the jsonl file paccking the attestations
	filePrefix      string
	outputDirectory string
}

// Validate the options in context with arguments
func (o *unpackOptions) Validate() error {
	errs := []error{}

	if o.archivePath == "" {
		errs = append(errs, errors.New("no jsonl bundle specified"))
	} else if !helpers.Exists(o.archivePath) {
		errs = append(errs, errors.New("specified jsonl file not found"))
	}

	if o.outputDirectory != "" {
		if !helpers.IsDir(o.outputDirectory) {
			errs = append(errs, errors.New("output directory not found or is not a directory"))
		}
	}

	return errors.Join(errs...)
}

func (o *unpackOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(
		&o.archivePath,
		"file", "f", "", "path to jsonl file packing the attestations",
	)
	cmd.PersistentFlags().StringVar(
		&o.filePrefix,
		"prefix", "", "prefix to use for generated files (defaults to jsonl file base)",
	)
	cmd.PersistentFlags().StringVarP(
		&o.outputDirectory, "out", "o", ".", "output directory",
	)
}

func addUnpack(parentCmd *cobra.Command) {
	opts := unpackOptions{}
	unpackCmd := &cobra.Command{
		Short: "unpacks attestations bundled in a jsonl file",
		Long: fmt.Sprintf(`
🥨 %s unpack: Extract files from a jsonl bundle

The unpack command opens a json file and extracts all the contained attestations
into single files. By default, the attstations will be extracted to numbered
files, named after the jsonl filename.

You can specify another file prefix for more consistent naming.

bnd unpack will do some simple checking on the jsonl lines to make sure lines are
parseable json.

`, appname),
		Use:           "unpack [flags] bundle.json [bundle.json...]",
		SilenceUsage:  false,
		SilenceErrors: true,
		Example: fmt.Sprintf(`
Extract atetstations from a jsonl file:

%s unpack attestations.jsonl

Same but with specifying a prefix for the generated files:

%s unpack --prefix "data-" attestations.jsonl 

This would result in a sequence of files like this:
     → data-00.json
     → data-01.json
     → data-02.json

`, appname, appname),
		PersistentPreRunE: initLogging,
		PreRunE: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				if args[0] != opts.archivePath && opts.archivePath != "" {
					return fmt.Errorf("only one bundle can be specified at a time")
				}
				opts.archivePath = args[0]
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}

			cmd.SilenceUsage = true

			if err := jsonl.UnpackBundleFile(
				opts.archivePath,
				jsonl.WithFilePrefix(opts.filePrefix),
				jsonl.WithOutputDirectory(opts.outputDirectory),
			); err != nil {
				return fmt.Errorf("unpacking jsonl bundle: %w", err)
			}

			return nil
		},
	}
	opts.AddFlags(unpackCmd)
	parentCmd.AddCommand(unpackCmd)
}
