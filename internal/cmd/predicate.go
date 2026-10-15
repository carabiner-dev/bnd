// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/carabiner-dev/command/subject"
	"github.com/carabiner-dev/hasher"
	v1 "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	"github.com/policylabs/collector/predicate"
	"github.com/policylabs/collector/statement/intoto"
	"github.com/policylabs/signer"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert/yaml"
)

type predicateOptions struct {
	signOptions
	signerSetOptions
	outFileOptions
	predicateFileOptions
	singleDigestOptions
	subject.Options
	SubjectHashes    []string
	SubjectPaths     []string
	SubjectAlgorithm string
}

// Validates the options in context with arguments
func (po *predicateOptions) Validate() error {
	errs := append([]error{},
		po.signOptions.Validate(),
		po.predicateFileOptions.Validate(),
		po.signerSetOptions.Validate(),
		po.outFileOptions.Validate(),
		po.Options.Validate(),
	)

	if len(po.SubjectHashes) == 0 && len(po.SubjectPaths) == 0 && len(po.Subjects) == 0 {
		errs = append(errs, errors.New("no subjects specified"))
	}

	if len(po.SubjectHashes) > 0 {
		if _, ok := subject.Algorithm(po.SubjectAlgorithm); !ok {
			errs = append(errs, fmt.Errorf("unknown hash algorithm %q", po.SubjectAlgorithm))
		}
	}

	if po.PredicatePath == "" {
		return fmt.Errorf("no predicate file specified")
	}

	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (po *predicateOptions) AddFlags(cmd *cobra.Command) {
	po.signOptions.AddFlags(cmd)
	po.predicateFileOptions.AddFlags(cmd)
	po.outFileOptions.AddFlags(cmd)

	po.signerSetOptions.AddFlags(cmd)
	po.singleDigestOptions.AddFlags(cmd)
	po.Options.AddFlags(cmd)

	cmd.PersistentFlags().StringSliceVar(
		&po.SubjectHashes, "hash-value", []string{}, "digest values to add as subjects (algorithm set with --hash-algo)",
	)

	cmd.PersistentFlags().StringVar(
		&po.SubjectAlgorithm, "hash-algo", "sha256", "algorithm used to hash the subjects",
	)

	cmd.PersistentFlags().StringSliceVarP(
		&po.SubjectPaths, "subject-file", "f", []string{}, "path to files to use as subjects",
	)
}

func addPredicate(parentCmd *cobra.Command) {
	opts := &predicateOptions{
		signerSetOptions: defaultSignerSetOptions(),
	}

	attCmd := &cobra.Command{
		Short:             "packs a new attestation into a bundle from a JSON predicate",
		Use:               "predicate",
		Example:           fmt.Sprintf(`%s predicate --type="example.com/v1" --subject=sha256:<digest> data.json`, appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		PreRunE: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 && opts.PredicatePath == "" {
				opts.PredicatePath = args[0]
			}

			if len(args) > 0 && opts.PredicatePath != "" && args[0] != opts.PredicatePath {
				return fmt.Errorf("predicate specified twice (-p and argument)")
			}

			return nil
		},
		RunE: func(_ *cobra.Command, args []string) error {
			// Validate the options
			if err := opts.Validate(); err != nil {
				return err
			}

			var f io.Reader
			f, err := os.Open(opts.PredicatePath)
			if err != nil {
				return fmt.Errorf("opening predicate file: %w", err)
			}

			predData, err := io.ReadAll(f)
			if err != nil {
				return fmt.Errorf("reading predicate data: %w", err)
			}

			if opts.ConvertYAML {
				predData, err = convertYaml(predData)
				if err != nil {
					return err
				}
			}

			optFn := []predicate.ParseOption{}
			if opts.PredicateType != "" {
				optFn = append(optFn, predicate.WithTypeHints(
					[]attestation.PredicateType{
						attestation.PredicateType(opts.PredicateType),
					}),
				)
			}
			pred, err := predicate.Parsers.Parse(predData, optFn...)
			if err != nil {
				return fmt.Errorf("parsing predicate data: %w", err)
			}

			// Create the new attestation
			statement := intoto.NewStatement(intoto.WithPredicate(pred))
			if opts.PredicateType != "" {
				statement.PredicateType = attestation.PredicateType(opts.PredicateType)
			}

			// Add the attestation subjects
			algo, _ := subject.Algorithm(opts.SubjectAlgorithm)
			for _, s := range opts.SubjectHashes {
				statement.Subject = append(statement.Subject, &v1.ResourceDescriptor{
					Digest: map[string]string{string(algo): s},
				})
			}

			// Subjects passed with --subject: digests or files to hash
			subjects, err := opts.ResourceDescriptors()
			if err != nil {
				return fmt.Errorf("resolving subjects: %w", err)
			}
			statement.Subject = append(statement.Subject, subjects...)

			// Generate the subjects of files passed in the arguments:
			hshr := hasher.New()
			hashes, err := hshr.HashFiles(opts.SubjectPaths)
			if err != nil {
				return fmt.Errorf("hashing passed files: %w", err)
			}
			statement.Subject = append(statement.Subject, hashes.ToResourceDescriptors()...)
			opts.applyToStatement(statement)

			// Marshal the attestation data
			attData, err := statement.ToJson()
			if err != nil {
				return fmt.Errorf("marshaling statement json: %w", err)
			}

			logrus.Debugf("ATTESTATION:\n%s\n/ATTESTATION\n", string(attData))

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

func convertYaml(in []byte) ([]byte, error) {
	datamap := &map[string]any{}
	if err := yaml.Unmarshal(in, datamap); err != nil {
		return nil, fmt.Errorf("parsing predicate YAML")
	}

	// Marshal to JSON again
	jsondata, err := json.Marshal(datamap)
	if err != nil {
		return nil, fmt.Errorf("marshalling jsondata: %w", err)
	}
	return jsondata, nil
}
