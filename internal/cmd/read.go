// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/collector"
	"github.com/carabiner-dev/collector/filters"
	"github.com/carabiner-dev/command"
	"github.com/carabiner-dev/jsonl"
	"github.com/spf13/cobra"

	"github.com/carabiner-dev/bnd/pkg/render"
)

type readOptions struct {
	sigstoreOptions
	collectorOptions
	outFileOptions
	subjectsOptions
	command.KeyOptions
	VerifySignatures bool
	predicates       bool
	statements       bool
	jsonl            bool
	predicateTypes   []string
}

// Validate checks the options
func (ro *readOptions) Validate() error {
	errs := []error{}
	errs = append(errs,
		ro.sigstoreOptions.Validate(),
		ro.collectorOptions.Validate(),
		ro.outFileOptions.Validate(),
		ro.KeyOptions.Validate(),
	)

	if ro.predicates && ro.statements {
		errs = append(errs, errors.New("only --statements or --predicates can be set at a time"))
	}

	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (ro *readOptions) AddFlags(cmd *cobra.Command) {
	ro.sigstoreOptions.AddFlags(cmd)
	ro.collectorOptions.AddFlags(cmd)
	ro.outFileOptions.AddFlags(cmd)
	ro.subjectsOptions.AddFlags(cmd)
	ro.KeyOptions.AddFlags(cmd)

	cmd.PersistentFlags().BoolVarP(
		&ro.VerifySignatures, "verify", "v", true, "verify the signatures of read attestations",
	)
	cmd.PersistentFlags().BoolVar(
		&ro.statements, "statements", false, "dump the bare statements (discard any envelopes)",
	)
	cmd.PersistentFlags().BoolVar(
		&ro.predicates, "predicates", false, "dump only the attestation predicates",
	)
	cmd.PersistentFlags().BoolVar(
		&ro.jsonl, "jsonl", false, "dump all read attestations in a JSONL bundle",
	)

	cmd.PersistentFlags().StringSliceVar(
		&ro.predicateTypes, "type", []string{}, "list of predicate types to match",
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

Read from the GitHub attestations store and output them as a jsonl file:

> bnd read --jsonl --out=attestations.jsonl github:owner/repo

Read attestations from a directory:

> bnd read fs:/home/files/attestations/

Read all SPDX attestations from a jsonl bundle, extraing the bare (unsigned)
SBOMs:

> bnd read --type="https://spdx.dev/Document" --predicates jsonl:attestations.jsonl


`, appname),
		Use: "read [flags] repo:collector/spec1 [repo:collector/spec2...]",
		// Example:           fmt.Sprintf(`%s read source`, appname),
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

			// Build the fetch options  from the specified options
			funcs, err := buildFetchOptionFuncs(opts)
			if err != nil {
				return err
			}

			// Fetch the attestations
			atts, err := agent.Fetch(context.Background(), funcs...)
			if err != nil {
				return fmt.Errorf("fetching attestations: %w", err)
			}

			var o io.Writer
			o = os.Stdout
			if opts.jsonl && opts.OutPath != "" {
				var closer func()
				o, closer, err = opts.OutputWriter()
				if err != nil {
					return fmt.Errorf("opening output file: %w", err)
				}
				defer closer()
			}

			// Parse any public keys passed in args
			keys, err := opts.ParseKeys()
			if err != nil {
				return fmt.Errorf("parsing public keys: %w", err)
			}

			renderer, err := render.New(
				render.WithVerifySignatures(opts.VerifySignatures),
				render.WithPublicKey(keys...),
			)
			if err != nil {
				return err
			}

			if !opts.jsonl {
				fmt.Println("\n🔎  Query Results:")
				fmt.Println("-----------------")
			}

			for i, a := range atts {
				switch {
				case opts.predicates && !opts.jsonl:
					fmt.Println(string(a.GetPredicate().GetData()))
					continue
				case opts.jsonl && !opts.predicates && !opts.statements:
					data, err := json.Marshal(a)
					if err != nil {
						return fmt.Errorf("marshaling envelope: %w", err)
					}
					// Writte the flattened data to the writer
					if _, err := io.Copy(o, jsonl.FlattenJSONStream(bytes.NewBuffer(data))); err != nil {
						return fmt.Errorf("flattening json data: %w", err)
					}
					if _, err := io.WriteString(o, "\n"); err != nil {
						return err
					}
				case opts.jsonl && opts.statements:
					data, err := json.Marshal(a.GetStatement())
					if err != nil {
						return err
					}
					if _, err := io.Copy(o, jsonl.FlattenJSONStream(bytes.NewBuffer(data))); err != nil {
						return fmt.Errorf("flattening json data: %w", err)
					}
					if _, err := io.WriteString(o, "\n"); err != nil {
						return err
					}
				case opts.jsonl && opts.predicates:
					// Writte the flattened data to the writer
					if _, err := io.Copy(o, jsonl.FlattenJSONStream(bytes.NewBuffer(a.GetPredicate().GetData()))); err != nil {
						return fmt.Errorf("flattening json data: %w", err)
					}
					if _, err := io.WriteString(o, "\n"); err != nil {
						return err
					}
				default:
					fmt.Printf("\nAttestation #%d\n", i)
					if err := renderer.DisplayEnvelopeDetails(os.Stdout, a); err != nil {
						return fmt.Errorf("rendering attestation: %w", err)
					}
				}
			}
			return nil
		},
	}
	opts.AddFlags(readCmd)
	parentCmd.AddCommand(readCmd)
}

func buildFetchOptionFuncs(opts *readOptions) ([]collector.FetchOptionsFunc, error) {
	funcs := []collector.FetchOptionsFunc{}
	enabledFilters := []attestation.Filter{}

	// If predicate types are defined, add a filter
	if len(opts.predicateTypes) > 0 {
		ptMap := map[attestation.PredicateType]struct{}{}
		for _, pt := range opts.predicateTypes {
			ptMap[attestation.PredicateType(pt)] = struct{}{}
		}
		enabledFilters = append(enabledFilters, &filters.PredicateTypeMatcher{
			PredicateTypes: ptMap,
		})
	}

	// If there are any subject hashses defined, add filters for them
	if len(opts.subjects) > 0 {
		hs, err := opts.getHashSet()
		if err != nil {
			return nil, fmt.Errorf("reading subject hashes: %w", err)
		}
		hashList := []map[string]string{}

		for _, b := range hs {
			m := map[string]string{}
			for algo, val := range b {
				m[algo.String()] = val
			}
			hashList = append(hashList, m)
		}
		enabledFilters = append(enabledFilters, &filters.SubjectHashMatcher{
			HashSets: hashList,
		})
	}

	if len(enabledFilters) > 0 {
		q := attestation.NewQuery()
		funcs = append(funcs, collector.WithQuery(q.WithFilter(enabledFilters...)))
	}
	return funcs, nil
}
