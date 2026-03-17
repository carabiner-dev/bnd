// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/collector"
	"github.com/carabiner-dev/command/keys"
	signer "github.com/carabiner-dev/signer/api/v1"
	"github.com/carabiner-dev/signer/key"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/carabiner-dev/bnd/pkg/bundle"
	"github.com/carabiner-dev/bnd/pkg/render"
)

const (
	lsHeaderPredicateType = "PREDICATE TYPE"
	lsHeaderSignerID      = "SIGNER IDENTITY"
	lsColumnGap           = 3
	lsDefaultWidth        = 80
)

type lsOptions struct {
	collectorOptions
	subjectsOptions
	keyOptions       keys.Options
	VerifySignatures bool
	predicateTypes   []string
}

func (lo *lsOptions) Validate() error {
	return errors.Join(
		lo.collectorOptions.Validate(),
		lo.keyOptions.Validate(),
	)
}

func (lo *lsOptions) AddFlags(cmd *cobra.Command) {
	lo.collectorOptions.AddFlags(cmd)
	lo.subjectsOptions.AddFlags(cmd)
	lo.keyOptions.AddFlags(cmd)

	cmd.PersistentFlags().BoolVarP(
		&lo.VerifySignatures, "verify", "v", true, "verify the signatures of read attestations",
	)
	cmd.PersistentFlags().StringSliceVar(
		&lo.predicateTypes, "type", []string{}, "list of predicate types to match",
	)
}

func addLs(parentCmd *cobra.Command) {
	opts := &lsOptions{}
	lsCmd := &cobra.Command{
		Short: "list attestations from source repositories",
		Long: fmt.Sprintf(`
%s ls

The ls subcommand lists attestations from a source repository showing a short
summary of each attestation's predicate type and signer identity in a two-column
table format.

Examples:

  %s ls jsonl:attestations.jsonl
  %s ls --type="https://spdx.dev/Document" jsonl:attestations.jsonl
  %s ls --key=key.pub github:owner/repo

`, appname, appname, appname, appname),
		Use:               "ls [flags] repo:collector/spec1 [repo:collector/spec2...]",
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		PreRunE: func(_ *cobra.Command, args []string) error {
			for _, arg := range args {
				if !slices.Contains(opts.collectors, arg) {
					opts.collectors = append(opts.collectors, arg)
				}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if len(opts.collectors) == 0 {
				return cmd.Help()
			}
			if err := opts.Validate(); err != nil {
				return fmt.Errorf("validating options: %w", err)
			}

			parsedKeys, err := opts.keyOptions.ParseKeys()
			if err != nil {
				return fmt.Errorf("parsing public keys: %w", err)
			}

			agent, err := opts.GetAgent(collector.WithKeys(parsedKeys...))
			if err != nil {
				return fmt.Errorf("creating collector agent: %w", err)
			}

			funcs := buildFetchOptionFuncs(&readOptions{
				collectorOptions: opts.collectorOptions,
				predicateTypes:   opts.predicateTypes,
			})

			var atts []attestation.Envelope
			if len(opts.subjects) > 0 {
				subs, err2 := opts.getSubjects()
				if err2 != nil {
					return err2
				}
				atts, err = agent.FetchAttestationsBySubject(cmd.Context(), subs)
			} else {
				atts, err = agent.Fetch(context.Background(), funcs...)
			}
			if err != nil {
				return fmt.Errorf("fetching attestations: %w", err)
			}

			rows, err := buildLsRows(opts, parsedKeys, atts)
			if err != nil {
				return fmt.Errorf("building rows: %w", err)
			}

			printLsTable(os.Stdout, rows)
			return nil
		},
	}
	opts.AddFlags(lsCmd)
	parentCmd.AddCommand(lsCmd)
}

// lsRow represents one output row in the ls table.
type lsRow struct {
	predicateType string
	identity      string
}

// buildLsRows extracts rows from the fetched attestations. Multiple signers
// produce multiple rows: the first carries the predicate type, subsequent
// ones have an empty predicate type so it is not repeated.
func buildLsRows(opts *lsOptions, verificationKeys []key.PublicKeyProvider, atts []attestation.Envelope) ([]lsRow, error) {
	renderer, err := render.New(
		render.WithVerifySignatures(opts.VerifySignatures),
		render.WithPublicKey(verificationKeys...),
	)
	if err != nil {
		return nil, err
	}

	tool := bundle.NewTool()
	var rows []lsRow

	for _, env := range atts {
		att, err := tool.ExtractAttestation(env)
		if err != nil {
			continue
		}

		predType := string(att.GetPredicateType())
		if predType == "" {
			predType = "[not defined]"
		}

		identities := extractIdentities(renderer, env, att)

		if len(identities) == 0 {
			rows = append(rows, lsRow{predicateType: predType, identity: "[unsigned]"})
			continue
		}

		for i, id := range identities {
			pt := ""
			if i == 0 {
				pt = predType
			}
			rows = append(rows, lsRow{predicateType: pt, identity: id})
		}
	}

	return rows, nil
}

// extractIdentities returns the signer identity slugs for an envelope.
func extractIdentities(r *render.Renderer, env attestation.Envelope, att attestation.Statement) []string {
	if !r.Options.VerifySignatures {
		return []string{"[not verified]"}
	}

	// Trigger verification
	verifyErr := env.Verify(r.Options.PublicKeys)

	v := att.GetVerification()
	if v == nil {
		if verifyErr != nil {
			return []string{"[unverified]"}
		}
		return []string{"[unsigned]"}
	}

	if !v.GetVerified() {
		return []string{"[unverified]"}
	}

	sigv, ok := v.(*signer.Verification)
	if !ok || sigv.GetSignature().GetIdentities() == nil {
		return []string{"[unsigned]"}
	}

	var slugs []string
	for _, id := range sigv.GetSignature().GetIdentities() {
		s := id.Slug()
		if s != "" {
			slugs = append(slugs, s)
		}
	}
	if len(slugs) == 0 {
		return []string{"[unsigned]"}
	}
	return slugs
}

// terminalWidth returns the width of the terminal or a default value.
func terminalWidth() int {
	fd := os.Stdout.Fd()
	w, _, err := term.GetSize(int(fd)) //nolint:gosec // fd is always a valid small descriptor
	if err != nil || w <= 0 {
		return lsDefaultWidth
	}
	return w
}

// printLsTable renders the two-column table to w, fitting within the
// terminal width. When the content is wider than the terminal, both
// columns are trimmed equally.
func printLsTable(w io.Writer, rows []lsRow) {
	totalWidth := terminalWidth()

	// Find the longest values in each column (including headers).
	maxPred := len(lsHeaderPredicateType)
	maxID := len(lsHeaderSignerID)
	for _, r := range rows {
		if len(r.predicateType) > maxPred {
			maxPred = len(r.predicateType)
		}
		if len(r.identity) > maxID {
			maxID = len(r.identity)
		}
	}

	// Compute column widths that fit the terminal.
	colPred, colID := fitColumns(maxPred, maxID, totalWidth)

	printRow := func(left, right string) {
		fmt.Fprintf(w, "%-*s%s\n", colPred+lsColumnGap, left, right) //nolint:errcheck // writing to terminal
	}

	// Print header
	printRow(lsHeaderPredicateType, lsHeaderSignerID)
	printRow(strings.Repeat("-", colPred), strings.Repeat("-", colID))

	// Print rows
	for _, r := range rows {
		printRow(truncate(r.predicateType, colPred), truncate(r.identity, colID))
	}
}

// fitColumns computes the width of each column so they fit within totalWidth.
// When the natural widths exceed the available space, the excess is trimmed
// equally from both columns.
func fitColumns(maxPred, maxID, totalWidth int) (colPred, colID int) {
	available := totalWidth - lsColumnGap
	if available < 2 {
		available = 2
	}

	needed := maxPred + maxID
	if needed <= available {
		return maxPred, maxID
	}

	// Trim equally from both columns
	excess := needed - available
	trimEach := excess / 2
	trimExtra := excess % 2

	colPred = maxPred - trimEach
	colID = maxID - trimEach - trimExtra

	// Ensure minimum width of 4 for each column
	if colPred < 4 {
		colPred = 4
		colID = available - colPred
	}
	if colID < 4 {
		colID = 4
		colPred = available - colID
	}

	return colPred, colID
}

// truncate shortens s to maxLen, replacing the last 3 characters with "..."
// if the string is too long.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
