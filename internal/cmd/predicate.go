// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/carabiner-dev/ampel/pkg/formats/predicate"
	"github.com/carabiner-dev/ampel/pkg/formats/statement/intoto"
	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/hasher"
	v1 "github.com/in-toto/attestation/go/v1"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert/yaml"
	"sigs.k8s.io/release-utils/helpers"
)

type predicateOptions struct {
	signOptions
	sigstoreOptions
	outFileOptions
	predicateFileOptions
	SubjectValues    []string
	SubjectHashes    []string
	SubjectPaths     []string
	SubjectAlgorithm string
}

func (po *predicateOptions) SubjectValuesToDigests() []map[string]string {
	if hashRegex == nil {
		hashRegex = regexp.MustCompile(hashRegexStr)
	}
	ret := []map[string]string{}
	for _, v := range po.SubjectValues {
		pts := hashRegex.FindStringSubmatch(v)
		if pts == nil {
			continue
		}
		ret = append(ret, map[string]string{
			pts[1]: pts[2],
		})
	}
	return ret
}

// Validates the options in context with arguments
func (po *predicateOptions) Validate() error {
	errs := append([]error{},
		po.signOptions.Validate(),
		po.predicateFileOptions.Validate(),
		po.sigstoreOptions.Validate(),
		po.outFileOptions.Validate(),
	)

	if len(po.SubjectHashes) == 0 && len(po.SubjectPaths) == 0 && len(po.SubjectValuesToDigests()) == 0 {
		errs = append(errs, errors.New("no subjects specified"))
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
	po.sigstoreOptions.AddFlags(cmd)
	po.outFileOptions.AddFlags(cmd)

	cmd.PersistentFlags().StringSliceVarP(
		&po.SubjectValues, "subject", "s", []string{}, "list of hashes (algo:value) or paths to files to add as subjects ",
	)

	cmd.PersistentFlags().StringSliceVar(
		&po.SubjectHashes, "hash-value", []string{}, "algorithm used to hash the subjects",
	)

	cmd.PersistentFlags().StringVar(
		&po.SubjectAlgorithm, "hash-algo", "sha256", "algorithm used to hash the subjects",
	)

	cmd.PersistentFlags().StringSliceVarP(
		&po.SubjectPaths, "subject-file", "f", []string{}, "path to files to use as subjects",
	)
}

// TODO:(move this to hasher)
var (
	hashRegexStr = `^(\bsha1\b|\bsha256\b|\bsha512\b|\bsha3\b|\bgitCommit\b):([a-f0-9]+)$`
	hashRegex    *regexp.Regexp
)

func addPredicate(parentCmd *cobra.Command) {
	opts := &predicateOptions{}
	attCmd := &cobra.Command{
		Short:             "packs a new attestation into a bundle from a JSON predicate",
		Use:               "predicate",
		Example:           fmt.Sprintf(`%s predicate --type="example.com/v1" --subject-hash=abc123 data.json`, appname),
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

			if hashRegex == nil {
				hashRegex = regexp.MustCompile(hashRegexStr)
			}
			// Parse the values

			// Transfer the files to the paths array
			vals := []string{}
			for _, v := range opts.SubjectValues {
				if helpers.Exists(v) {
					opts.SubjectPaths = append(opts.SubjectPaths, v)
					continue
				}
				res := hashRegex.FindStringSubmatch(v)
				if res == nil {
					return fmt.Errorf("invalid subject: %q", v)
				}
				vals = append(vals, v)
			}

			opts.SubjectValues = vals
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
			for _, s := range opts.SubjectHashes {
				statement.Subject = append(statement.Subject, &v1.ResourceDescriptor{
					Digest: map[string]string{
						opts.SubjectAlgorithm: s,
					},
				})
			}

			for _, h := range opts.SubjectValuesToDigests() {
				logrus.Infof("added %+v", h)
				statement.AddSubject(&v1.ResourceDescriptor{
					Digest: h,
				})
			}

			// Generate the subjects of files passed in the arguments:
			hshr := hasher.New()
			hashes, err := hshr.HashFiles(opts.SubjectPaths)
			if err != nil {
				return fmt.Errorf("hashing passed files: %w", err)
			}
			statement.Subject = append(statement.Subject, hashes.ToResourceDescriptors()...)

			// Marshal the attestation data
			attData, err := statement.ToJson()
			if err != nil {
				return fmt.Errorf("marshaling statement json: %w", err)
			}

			logrus.Debugf("ATTESTATION:\n%s\n/ATTESTATION\n", string(attData))

			signer := getSigner(&opts.sigstoreOptions, &opts.signOptions)

			bundle, err := signer.SignStatement(attData)
			if err != nil {
				return fmt.Errorf("writing signing statement: %w", err)
			}

			o, closer, err := opts.OutputWriter()
			if err != nil {
				return fmt.Errorf("getting output stream: %w", err)
			}
			defer closer()

			if err := signer.WriteBundle(bundle, o); err != nil {
				return err
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
