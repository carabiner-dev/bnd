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

	"github.com/carabiner-dev/bnd/internal/supplychain"
	"github.com/carabiner-dev/bnd/pkg/bundle"
	"github.com/carabiner-dev/bnd/pkg/render"
)

const (
	lsHeaderPredicateType = "PREDICATE TYPE"
	lsHeaderSignerID      = "SIGNER IDENTITY"
	lsHeaderSubject       = "SUBJECT"
	lsColumnGap           = 3
	lsNumColumns          = 3
	lsDefaultWidth        = 80
)

type lsOptions struct {
	collectorOptions
	subjectsOptions
	keyOptions       keys.Options
	supplyChainOpts  supplychain.Options
	VerifySignatures bool
	predicateTypes   []string
}

func (lo *lsOptions) Validate() error {
	return errors.Join(
		lo.collectorOptions.Validate(),
		lo.keyOptions.Validate(),
		lo.supplyChainOpts.Validate(),
	)
}

func (lo *lsOptions) AddFlags(cmd *cobra.Command) {
	lo.collectorOptions.AddFlags(cmd)
	lo.subjectsOptions.AddFlags(cmd)
	lo.keyOptions.AddFlags(cmd)
	lo.supplyChainOpts.AddFlags(cmd)

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
			if err := opts.Validate(); err != nil {
				return fmt.Errorf("validating options: %w", err)
			}

			// Merge supply chain config into collectors and keys
			if conf := opts.supplyChainOpts.GetSupplyChainConf(); conf != nil {
				opts.AddCollectorStrings(conf.GetRepositories())
				scKeys, err := conf.GetPublicKeys()
				if err != nil {
					return fmt.Errorf("getting supply chain keys: %w", err)
				}
				opts.keyOptions.AddKeys(scKeys...)
			}

			if len(opts.collectors) == 0 {
				return cmd.Help()
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

			hasSubjects := len(opts.subjects) > 0
			hasTypes := len(opts.predicateTypes) > 0

			switch {
			case hasSubjects && hasTypes:
				printLsTableFiltered(os.Stdout, rows, opts.subjects, opts.predicateTypes)
			case hasSubjects:
				printLsTableBySubject(os.Stdout, rows, opts.subjects)
			case hasTypes:
				printLsTableByType(os.Stdout, rows, opts.predicateTypes)
			default:
				printLsTable(os.Stdout, rows)
			}
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
	subject       string
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

		subjectStr := extractSubjectSlug(att)
		identities := extractIdentities(renderer, env, att)

		if len(identities) == 0 {
			rows = append(rows, lsRow{predicateType: predType, identity: "[unsigned]", subject: subjectStr})
			continue
		}

		for i, id := range identities {
			pt := ""
			sub := ""
			if i == 0 {
				pt = predType
				sub = subjectStr
			}
			rows = append(rows, lsRow{predicateType: pt, identity: id, subject: sub})
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

// extractSubjectSlug returns a short string identifying the first subject of
// an attestation. It prefers the first digest hash found; if there are no
// digests it falls back to the subject name.
func extractSubjectSlug(att attestation.Statement) string {
	subjects := att.GetSubjects()
	if len(subjects) == 0 {
		return ""
	}
	s := subjects[0]

	// Prefer the first hash
	for algo, val := range s.GetDigest() {
		return algo + ":" + val
	}

	// Fall back to name
	if name := s.GetName(); name != "" {
		return name
	}
	return ""
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

// printLsTable renders the three-column table to w. Each column is
// exactly 1/3 of the terminal width (minus inter-column gaps).
func printLsTable(w io.Writer, rows []lsRow) {
	totalWidth := terminalWidth()
	colWidth := columnWidth(totalWidth)

	printRow := func(a, b, c string) {
		fmt.Fprintf(w, "%-*s%-*s%s\n", colWidth+lsColumnGap, a, colWidth+lsColumnGap, b, c) //nolint:errcheck // writing to terminal
	}

	// Print header
	printRow(lsHeaderPredicateType, lsHeaderSignerID, lsHeaderSubject)
	printRow(strings.Repeat("-", colWidth), strings.Repeat("-", colWidth), strings.Repeat("-", colWidth))

	// Print rows
	for _, r := range rows {
		printRow(truncate(r.predicateType, colWidth), truncateIdentity(r.identity, colWidth), truncate(r.subject, colWidth))
	}
}

// printLsTableBySubject renders a two-column table (predicate type + identity)
// preceded by a header showing the subjects being filtered. Each column gets
// 50% of the terminal width.
func printLsTableBySubject(w io.Writer, rows []lsRow, subjects []string) {
	totalWidth := terminalWidth()
	colWidth := (totalWidth - lsColumnGap) / 2

	for _, s := range subjects {
		fmt.Fprintf(w, "Subject: %s\n", s) //nolint:errcheck // writing to terminal
	}
	fmt.Fprintln(w) //nolint:errcheck // writing to terminal

	printRow := func(a, b string) {
		fmt.Fprintf(w, "%-*s%s\n", colWidth+lsColumnGap, a, b) //nolint:errcheck // writing to terminal
	}

	printRow(lsHeaderPredicateType, lsHeaderSignerID)
	printRow(strings.Repeat("-", colWidth), strings.Repeat("-", colWidth))

	for _, r := range rows {
		printRow(truncate(r.predicateType, colWidth), truncateIdentity(r.identity, colWidth))
	}
}

// printLsTableByType renders a two-column table (identity + subject)
// preceded by a header showing the predicate types being filtered. Each
// column gets 50% of the terminal width.
func printLsTableByType(w io.Writer, rows []lsRow, predicateTypes []string) {
	totalWidth := terminalWidth()
	colWidth := (totalWidth - lsColumnGap) / 2

	for _, pt := range predicateTypes {
		fmt.Fprintf(w, "Predicate type: %s\n", pt) //nolint:errcheck // writing to terminal
	}
	fmt.Fprintln(w) //nolint:errcheck // writing to terminal

	printRow := func(a, b string) {
		fmt.Fprintf(w, "%-*s%s\n", colWidth+lsColumnGap, a, b) //nolint:errcheck // writing to terminal
	}

	printRow(lsHeaderSignerID, lsHeaderSubject)
	printRow(strings.Repeat("-", colWidth), strings.Repeat("-", colWidth))

	for _, r := range rows {
		printRow(truncateIdentity(r.identity, colWidth), truncate(r.subject, colWidth))
	}
}

// printLsTableFiltered renders a single-column table of identities when both
// subject and predicate type filters are active. The filters are printed above.
func printLsTableFiltered(w io.Writer, rows []lsRow, subjects, predicateTypes []string) {
	totalWidth := terminalWidth()

	for _, pt := range predicateTypes {
		fmt.Fprintf(w, "Predicate type: %s\n", pt) //nolint:errcheck // writing to terminal
	}
	for _, s := range subjects {
		fmt.Fprintf(w, "Subject: %s\n", s) //nolint:errcheck // writing to terminal
	}
	fmt.Fprintln(w) //nolint:errcheck // writing to terminal

	colWidth := totalWidth
	fmt.Fprintln(w, lsHeaderSignerID)                           //nolint:errcheck // writing to terminal
	fmt.Fprintln(w, strings.Repeat("-", len(lsHeaderSignerID))) //nolint:errcheck // writing to terminal

	for _, r := range rows {
		fmt.Fprintln(w, truncateIdentity(r.identity, colWidth)) //nolint:errcheck // writing to terminal
	}
}

// columnWidth returns the width of each column given the total terminal width.
// Each of the three columns gets an equal share of the available space after
// subtracting the inter-column gaps.
func columnWidth(totalWidth int) int {
	available := totalWidth - lsColumnGap*(lsNumColumns-1)
	if available < lsNumColumns {
		available = lsNumColumns
	}
	return available / lsNumColumns
}

// truncateIdentity shortens an identity string to maxLen. When truncation is
// needed, the type prefix (everything up to and including the first "::") is
// kept in full, followed by "..." and as much of the tail of the remaining
// string as fits. For example: "sigstore::...er@example.com".
func truncateIdentity(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}

	prefix := ""
	rest := s
	if idx := strings.Index(s, "::"); idx >= 0 {
		prefix = s[:idx+2]
		rest = s[idx+2:]
	}

	ellipsis := "..."
	available := maxLen - len(prefix) - len(ellipsis)
	if available <= 0 {
		// Not enough room for prefix + ellipsis + tail, fall back to simple truncate
		return truncate(s, maxLen)
	}

	// Show the tail of the rest
	tail := rest[len(rest)-available:]
	return prefix + ellipsis + tail
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
