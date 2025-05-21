// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	ampelb "github.com/carabiner-dev/ampel/pkg/formats/envelope/bundle"
	"github.com/carabiner-dev/jsonl"
	"github.com/spf13/cobra"

	"github.com/carabiner-dev/bnd/pkg/bundle"
)

type inspectOptions struct {
	bundleOptions
}

// Validates the options in context with arguments
func (o *inspectOptions) Validate() error {
	return errors.Join(
		o.bundleOptions.Validate(),
	)
}

func (o *inspectOptions) AddFlags(cmd *cobra.Command) {
	o.bundleOptions.AddFlags(cmd)
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

			fmt.Println("\n🔎  Bundle Details:")
			fmt.Println("-------------------")

			if strings.HasSuffix(opts.Path, ".jsonl") {
				for i, r := range jsonl.IterateBundle(reader) {
					if r == nil {
						fmt.Printf("Unable to parse line #%d\n", i)
						continue
					}
					fmt.Printf("Attestation #%d\n", i)
					if err := printEnvelopeDetails(r); err != nil {
						return err
					}
				}
				return nil
			}

			// If it's just a single json:
			return printEnvelopeDetails(reader)
		},
	}
	opts.AddFlags(extractCmd)
	parentCmd.AddCommand(extractCmd)
}

func printEnvelopeDetails(reader io.Reader) error {
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

	verifyErr := envelope.Verify()

	att, err := tool.ExtractAttestation(envelope)
	if err != nil {
		return fmt.Errorf("unable to extract attestation from bundle")
	}

	mediatype := "unknown"
	if bndl, ok := envelope.(*ampelb.Envelope); ok {
		mediatype = bndl.GetMediaType()
	}

	fmt.Printf("✉️  Envelope Media Type: %s\n", mediatype)
	idstr := "[✗ not signed]\n"
	if verifyErr != nil {
		idstr = fmt.Sprintf("[error: %s]", err)
	}
	if att.GetVerification() != nil {
		idstr = "[No identity found]\n"
		if att.GetVerification().GetSignature().GetIdentities() != nil {
			idstr = ""
			for i, id := range att.GetVerification().GetSignature().GetIdentities() {
				if i > 0 {
					idstr += strings.Repeat(" ", 19)
				}
				idstr += id.Slug() + "\n"
			}
		}
	}
	fmt.Printf("🔏 Signer identity: %s", idstr)
	if att != nil {
		fmt.Println("📃 Attestation Details:")
		fmt.Printf("   Predicate Type: %s", att.GetPredicateType())
		if att.GetPredicateType() == "" {
			fmt.Print("[not defined]")
		}
		fmt.Println("")

		if att.GetSubjects() != nil {
			fmt.Printf("   Attestation Subjects:\n")
			for _, s := range att.GetSubjects() {
				if s.GetName() != "" {
					fmt.Println("   - " + s.GetName())
				}

				i := 0
				for algo, val := range s.GetDigest() {
					if i == 0 {
						if s.GetName() == "" {
							fmt.Print("   - ")
						} else {
							fmt.Print("     ")
						}
						fmt.Printf("%s: %s\n", algo, val)
					}
					i++
				}
			}
		} else {
			fmt.Println("⚠️ Attestation has no subjects")
		}
	} else {
		fmt.Println("⚠️ No attestation found in envelope")
	}
	fmt.Println("")
	return nil
}
