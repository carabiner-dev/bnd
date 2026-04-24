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
	"github.com/carabiner-dev/termtable"
	"github.com/spf13/cobra"

	"github.com/carabiner-dev/bnd/internal/supplychain"
	"github.com/carabiner-dev/bnd/pkg/bundle"
	"github.com/carabiner-dev/bnd/pkg/render"
)

const (
	lsHeaderPredicateType = "PREDICATE TYPE"
	lsHeaderSignerID      = "SIGNER IDENTITY"
	lsHeaderSubject       = "SUBJECT"
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

			// Check if the supply chain config should be used
			useConfig, notice := opts.supplyChainOpts.ShouldUseConfig(len(opts.collectors) > 0)
			if notice != "" {
				fmt.Fprintln(os.Stderr, notice)
			}
			if useConfig {
				conf := opts.supplyChainOpts.GetSupplyChainConf()
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

			funcs := buildFetchOptionFuncs(&getOptions{
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

		subjectSlugs := extractSubjectSlugs(att)
		if len(subjectSlugs) == 0 {
			subjectSlugs = []string{""}
		}
		identities := extractIdentities(renderer, env, att)
		if len(identities) == 0 {
			identities = []string{"[unsigned]"}
		}

		// First row carries predicate type, first identity and first subject.
		// Additional identities and additional subjects each get their own
		// row with the earlier-shown columns left blank.
		for i, id := range identities {
			pt := ""
			sub := ""
			if i == 0 {
				pt = predType
				sub = subjectSlugs[0]
			}
			rows = append(rows, lsRow{predicateType: pt, identity: id, subject: sub})
		}
		for i := 1; i < len(subjectSlugs); i++ {
			rows = append(rows, lsRow{subject: subjectSlugs[i]})
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
		s := id.Principal()
		if s != "" {
			slugs = append(slugs, s)
		}
	}
	if len(slugs) == 0 {
		return []string{"[unsigned]"}
	}
	return slugs
}

// hashPriority lists digest algorithms in the order they should be picked
// when a subject carries more than one. sha256 is preferred first; the rest
// are ordered from strongest to weakest.
var hashPriority = []string{
	"sha256",
	"sha512",
	"sha384",
	"sha3-512",
	"sha3-384",
	"sha3-256",
	"sha3",
	"sha224",
	"sha1",
	"gitCommit",
	"md5",
}

// pickDigest returns the algorithm and value of the preferred digest in the
// given map, following hashPriority. Unknown algorithms are considered last
// and selected in a stable (alphabetical) order.
func pickDigest(digests map[string]string) (algo, value string) {
	for _, a := range hashPriority {
		if v, ok := digests[a]; ok {
			return a, v
		}
	}
	var algos []string
	for k := range digests {
		algos = append(algos, k)
	}
	slices.Sort(algos)
	for _, a := range algos {
		return a, digests[a]
	}
	return "", ""
}

// extractSubjectSlugs returns a short string identifying each subject of an
// attestation. For each subject it prefers the sha256 digest, falling back to
// the strongest available hash and finally to the subject name. Subjects with
// neither a digest nor a name are skipped.
func extractSubjectSlugs(att attestation.Statement) []string {
	subjects := att.GetSubjects()
	slugs := make([]string, 0, len(subjects))
	for _, s := range subjects {
		slug := ""
		if algo, val := pickDigest(s.GetDigest()); algo != "" {
			slug = algo + ":" + val
		}
		if slug == "" {
			slug = s.GetName()
		}
		if slug != "" {
			slugs = append(slugs, slug)
		}
	}
	return slugs
}

// lsBorderSet returns the border glyph set used by every ls table.
// Horizontal runs render as ASCII '-' so the rule under the header
// looks like the pre-termtable version. Verticals and junctions are
// spaces — never drawn because the table has `border: none` and only
// the header row opts back in via `border-bottom: solid`.
func lsBorderSet() termtable.BorderSet {
	b := termtable.BorderSet{
		Horizontal: '-',
		Vertical:   ' ',
	}
	for i := range b.Joins {
		b.Joins[i] = ' '
	}
	return b
}

// newLsTable builds a borderless termtable with the ls conventions
// applied: dash horizontal rule glyphs, 1-column padding on each
// side of content, no default borders anywhere, and the layout
// pinned to 100 % of the terminal width (overriding termtable's
// default 90 % ceiling).
func newLsTable() *termtable.Table {
	return termtable.NewTable(
		termtable.WithBorder(lsBorderSet()),
		termtable.WithTargetWidthPercent(100),
		termtable.WithTableStyle("border: none"),
	)
}

// addLsHeader appends the column-header row with an underline. Cells
// are passed as CellOption slices so callers can supply the uppercased
// column titles in one place.
func addLsHeader(t *termtable.Table, titles ...string) {
	hdr := t.AddHeader(termtable.WithRowBorderBottom(termtable.BorderEdgeSolid))
	for _, title := range titles {
		hdr.AddCell(termtable.WithContent(title))
	}
}

// equalColumnWidths pins every column to an equal share of the
// table target — the bnd "fixed thirds" look applied via termtable's
// percent-width support. Pass n = table.NumColumns() (or the column
// count you'll populate before writing).
func equalColumnWidths(t *termtable.Table, n int) {
	if n < 1 {
		return
	}
	pct := 100 / n
	for i := range n {
		t.Column(i).Style(fmt.Sprintf("white-space: nowrap; text-overflow: ellipsis; width: %d%%", pct))
	}
}

// printLsTable renders the three-column table to w.
func printLsTable(w io.Writer, rows []lsRow) {
	t := newLsTable()
	equalColumnWidths(t, 3)
	addLsHeader(t, lsHeaderPredicateType, lsHeaderSignerID, lsHeaderSubject)

	budget := identityBudget(t, 3)
	for _, r := range rows {
		row := t.AddRow()
		row.AddCell(termtable.WithContent(r.predicateType))
		row.AddCell(termtable.WithContent(truncateIdentity(r.identity, budget)))
		row.AddCell(termtable.WithContent(r.subject))
	}
	_, _ = t.WriteTo(w) //nolint:errcheck // writing to terminal
}

// printLsTableBySubject renders a two-column table (predicate type +
// identity) preceded by a header showing the subjects being filtered.
func printLsTableBySubject(w io.Writer, rows []lsRow, subjects []string) {
	for _, s := range subjects {
		fmt.Fprintf(w, "Subject: %s\n", s) //nolint:errcheck // writing to terminal
	}
	fmt.Fprintln(w) //nolint:errcheck // writing to terminal

	t := newLsTable()
	equalColumnWidths(t, 2)
	addLsHeader(t, lsHeaderPredicateType, lsHeaderSignerID)

	budget := identityBudget(t, 2)
	for _, r := range rows {
		row := t.AddRow()
		row.AddCell(termtable.WithContent(r.predicateType))
		row.AddCell(termtable.WithContent(truncateIdentity(r.identity, budget)))
	}
	_, _ = t.WriteTo(w) //nolint:errcheck // writing to terminal
}

// printLsTableByType renders a two-column table (identity + subject)
// preceded by a header showing the predicate types being filtered.
func printLsTableByType(w io.Writer, rows []lsRow, predicateTypes []string) {
	for _, pt := range predicateTypes {
		fmt.Fprintf(w, "Predicate type: %s\n", pt) //nolint:errcheck // writing to terminal
	}
	fmt.Fprintln(w) //nolint:errcheck // writing to terminal

	t := newLsTable()
	equalColumnWidths(t, 2)
	addLsHeader(t, lsHeaderSignerID, lsHeaderSubject)

	budget := identityBudget(t, 2)
	for _, r := range rows {
		row := t.AddRow()
		row.AddCell(termtable.WithContent(truncateIdentity(r.identity, budget)))
		row.AddCell(termtable.WithContent(r.subject))
	}
	_, _ = t.WriteTo(w) //nolint:errcheck // writing to terminal
}

// printLsTableFiltered renders a single-column table of identities when both
// subject and predicate type filters are active. The filters are printed above.
func printLsTableFiltered(w io.Writer, rows []lsRow, subjects, predicateTypes []string) {
	for _, pt := range predicateTypes {
		fmt.Fprintf(w, "Predicate type: %s\n", pt) //nolint:errcheck // writing to terminal
	}
	for _, s := range subjects {
		fmt.Fprintf(w, "Subject: %s\n", s) //nolint:errcheck // writing to terminal
	}
	fmt.Fprintln(w) //nolint:errcheck // writing to terminal

	t := newLsTable()
	t.Column(0).Style("white-space: nowrap; text-overflow: ellipsis")
	addLsHeader(t, lsHeaderSignerID)

	budget := identityBudget(t, 1)
	for _, r := range rows {
		row := t.AddRow()
		row.AddCell(termtable.WithContent(truncateIdentity(r.identity, budget)))
	}
	_, _ = t.WriteTo(w) //nolint:errcheck // writing to terminal
}

// identityBudget estimates the content width allotted to the identity
// column so truncateIdentity can preserve the "type::" prefix. termtable
// handles overflow natively via text-overflow: ellipsis, but its default
// truncation cuts the tail of the string, losing the prefix. Pre-trimming
// keeps the prefix visible. Pass ncols as the number of columns the
// table will end up with (the call sites know this statically).
func identityBudget(t *termtable.Table, ncols int) int {
	if ncols < 1 {
		ncols = 1
	}
	target := t.ResolvedTargetWidth()
	// Overhead: seam per column gap + 2 chars of padding per column.
	share := (target - ncols*3) / ncols
	if share < 20 {
		return 20
	}
	return share
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
