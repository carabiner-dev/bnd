// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTruncate(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{"no-truncation", "hello", 10, "hello"},
		{"exact-fit", "hello", 5, "hello"},
		{"truncate", "hello world", 8, "hello..."},
		{"very-short-max", "hello", 3, "hel"},
		{"empty", "", 5, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, truncate(tt.input, tt.maxLen))
		})
	}
}

func TestTruncateIdentity(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name     string
		input    string
		maxLen   int
		expected []string // substrings the result must contain
	}{
		{
			"fits",
			"sigstore::token.actions.githubusercontent.com::user@example.com",
			200,
			[]string{"sigstore::", "user@example.com"},
		},
		{
			"keeps-prefix-on-truncate",
			"sigstore::https://token.actions.githubusercontent.com::user@example.com",
			30,
			[]string{"sigstore::", "..."},
		},
		{
			"no-prefix-keeps-tail",
			"abcdefghij",
			5,
			[]string{"...ij"}, // no "::" prefix — ellipsis + tail
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := truncateIdentity(tt.input, tt.maxLen)
			require.LessOrEqual(t, len(got), tt.maxLen)
			for _, sub := range tt.expected {
				require.Contains(t, got, sub)
			}
		})
	}
}

func TestPrintLsTable(t *testing.T) {
	t.Parallel()
	rows := []lsRow{
		{"https://spdx.dev/Document", "sigstore::accounts.google.com::user@example.com", "sha256:abc123"},
		{"https://slsa.dev/provenance/v1", "key::ecdsa::6F64FADA", "sha256:def456"},
		{"", "key::rsa::ABCD1234", ""},
	}

	var buf bytes.Buffer
	printLsTable(&buf, rows)
	output := buf.String()
	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")

	// Header row + header-underline rule + 3 data rows = 5 lines.
	require.GreaterOrEqual(t, len(lines), 5, "header + rule + 3 data rows")

	// Header line carries the uppercase titles.
	require.Contains(t, lines[0], "PREDICATE TYPE")
	require.Contains(t, lines[0], "SIGNER IDENTITY")
	require.Contains(t, lines[0], "SUBJECT")

	// Second line is the header's bottom-border rule: dashes.
	require.Contains(t, lines[1], "-")

	// First data row has predicate type and subject.
	require.Contains(t, lines[2], "spdx.dev")
	require.Contains(t, lines[2], "sha256:abc123")

	// Third row (second identity for slsa) should not repeat predicate type.
	require.Contains(t, lines[4], "key::rsa::ABCD1234")
	idx := strings.Index(lines[4], "key::rsa")
	require.GreaterOrEqual(t, idx, 0, "identity must be present in line")
	predCol := strings.TrimRight(lines[4][:idx], " ")
	require.Empty(t, predCol, "predicate column on continuation row must be blank")
}

func TestPrintLsTable_Empty(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	printLsTable(&buf, nil)
	output := buf.String()

	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
	// Header + rule line = 2 lines for an empty table.
	require.Len(t, lines, 2, "header + rule for empty table")
	require.Contains(t, lines[0], "PREDICATE TYPE")
	require.Contains(t, lines[1], "-")
}

func TestPrintLsTableNoFramingGlyphs(t *testing.T) {
	t.Parallel()
	rows := []lsRow{
		{"https://spdx.dev/Document", "sigstore::accounts.google.com::user@example.com", "sha256:abc123"},
	}
	var buf bytes.Buffer
	printLsTable(&buf, rows)
	output := buf.String()

	// No box-drawing glyphs or ASCII frame characters — only the dash
	// rule under the header.
	for _, r := range "│┌┐└┘├┤┬┴┼+|═║╔╗╚╝╠╣╦╩╬" {
		require.NotContains(t, output, string(r), "unexpected frame glyph %q", r)
	}
}
