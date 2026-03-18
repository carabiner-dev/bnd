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

func TestColumnWidth(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name       string
		totalWidth int
		want       int
	}{
		{"standard-80", 80, 24},
		{"wide-120", 120, 38},
		{"narrow-30", 30, 8},
		{"very-narrow", 9, 1},
		{"minimum-clamp", 2, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := columnWidth(tt.totalWidth)
			require.Equal(t, tt.want, got)
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
	require.GreaterOrEqual(t, len(lines), 5, "header + separator + 3 data rows")

	// Header line
	require.Contains(t, lines[0], "PREDICATE TYPE")
	require.Contains(t, lines[0], "SIGNER IDENTITY")
	require.Contains(t, lines[0], "SUBJECT")

	// Separator line
	require.Contains(t, lines[1], "---")

	// First data row has predicate type and subject
	require.Contains(t, lines[2], "spdx.dev")
	require.Contains(t, lines[2], "sha256:abc123")

	// Third row (second identity for slsa) should not repeat predicate type
	require.Contains(t, lines[4], "key::rsa::ABCD1234")
	// The predicate column should be blank
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
	require.Len(t, lines, 2, "just header + separator for empty table")
}
