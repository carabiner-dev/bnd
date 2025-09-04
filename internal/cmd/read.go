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
	"github.com/carabiner-dev/jsonl"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/carabiner-dev/bnd/pkg/render"
)

type readOptions struct {
	sigstoreOptions
	collectorOptions
	outFileOptions
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

			funcs := []collector.FetchOptionsFunc{}
			enabledFilters := []attestation.Filter{}
			q := attestation.NewQuery()

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

			if len(enabledFilters) > 0 {
				funcs = append(funcs, collector.WithQuery(q.WithFilter(enabledFilters...)))
			}

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

			renderer, err := render.New(render.WithVerifySignatures(opts.VerifySignatures))
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
					if err := marshalEnvelopeToJsonl(o, a); err != nil {
						return fmt.Errorf("flattening envelope: %w", err)
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

// TODO(puerco): Once https://github.com/carabiner-dev/collector/issues/5
// is fixed, change this to use just json.Marshal
func marshalEnvelopeToJsonl(w io.Writer, e attestation.Envelope) error {
	var data []byte
	var err error
	// TODO(puerco): Check if it implements unmaarshaler
	if msg, ok := e.(proto.Message); ok {
		data, err = protojson.MarshalOptions{
			Multiline: false,
		}.Marshal(msg)
	} else {
		data, err = json.Marshal(e)
	}
	if err != nil {
		return fmt.Errorf("error marshaling envelope data: %w", err)
	}

	// Writte the flattened data to the writer
	if _, err := io.Copy(w, jsonl.FlattenJSONStream(bytes.NewBuffer(data))); err != nil {
		return fmt.Errorf("flattening json data: %w", err)
	}
	if _, err := io.WriteString(w, "\n"); err != nil {
		return err
	}
	return nil
}
