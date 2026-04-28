// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/carabiner-dev/signer"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type statementOptions struct {
	signOptions
	signerSetOptions
	outFileOptions
	StatementPath string
}

// Validates the options in context with arguments
func (so *statementOptions) Validate() error {
	errs := append([]error{},
		so.signOptions.Validate(),
		so.outFileOptions.Validate(),
		so.signerSetOptions.Validate(),
	)

	if so.StatementPath == "" {
		errs = append(errs, errors.New("attestation path is empty"))
	}
	return errors.Join(errs...)
}

func (so *statementOptions) AddFlags(cmd *cobra.Command) {
	so.signerSetOptions.AddFlags(cmd)

	so.signOptions.AddFlags(cmd)
	so.outFileOptions.AddFlags(cmd)

	cmd.PersistentFlags().StringVarP(
		&so.StatementPath, "statement", "s", "",
		"Path to the in-toto statement file",
	)
}

func addStatement(parentCmd *cobra.Command) {
	opts := &statementOptions{
		signerSetOptions: defaultSignerSetOptions(),
	}
	attCmd := &cobra.Command{
		Short:             "binds an in-toto attestation in a signed bundle",
		Use:               "statement",
		Example:           fmt.Sprintf("%s statement file.intoto.json ", appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 && opts.StatementPath != "" {
				return errors.New("statement path specified twice (positional argument and flag)")
			}
			if len(args) > 0 {
				opts.StatementPath = args[0]
			}
			return nil
		},
		RunE: func(_ *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return fmt.Errorf("validating options: %w", err)
			}

			var f io.Reader
			f, err := os.Open(opts.StatementPath)
			if err != nil {
				return fmt.Errorf("opening statement file")
			}

			attData, err := io.ReadAll(f)
			if err != nil {
				return fmt.Errorf("reading statement data: %w", err)
			}

			sg, err := signer.NewSignerFromSet(opts.SignerSet)
			if err != nil {
				return fmt.Errorf("building signer: %w", err)
			}
			defer func() {
				if err := sg.Close(); err != nil {
					logrus.Warnf("closing signer credentials: %v", err)
				}
			}()

			artifact, err := sg.SignStatement(attData)
			if err != nil {
				return fmt.Errorf("signing statement: %w", err)
			}

			o, closer, err := opts.OutputWriter()
			if err != nil {
				return fmt.Errorf("getting output stream: %w", err)
			}
			defer closer()

			if _, err := artifact.WriteTo(o); err != nil {
				return fmt.Errorf("writing artifact: %w", err)
			}
			return nil
		},
	}
	opts.AddFlags(attCmd)
	parentCmd.AddCommand(attCmd)
}
