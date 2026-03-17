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

func TestFitColumns(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name             string
		maxPred, maxID   int
		totalWidth       int
		wantPred, wantID int
	}{
		{"fits", 20, 20, 80, 20, 20},
		{"exact-fit", 20, 20, 43, 20, 20},
		{"trim-equally", 30, 30, 43, 20, 20},
		{"minimum-width", 50, 50, 15, 6, 6},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			colPred, colID := fitColumns(tt.maxPred, tt.maxID, tt.totalWidth)
			require.Equal(t, tt.wantPred, colPred, "predicate column width")
			require.Equal(t, tt.wantID, colID, "identity column width")
			require.LessOrEqual(t, colPred+colID+lsColumnGap, tt.totalWidth, "total must fit")
		})
	}
}

func TestPrintLsTable(t *testing.T) {
	t.Parallel()
	rows := []lsRow{
		{"https://spdx.dev/Document", "sigstore::accounts.google.com::user@example.com"},
		{"https://slsa.dev/provenance/v1", "key::ecdsa::6F64FADA"},
		{"", "key::rsa::ABCD1234"},
	}

	var buf bytes.Buffer
	printLsTable(&buf, rows)
	output := buf.String()

	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
	require.GreaterOrEqual(t, len(lines), 5, "header + separator + 3 data rows")

	// Header line
	require.Contains(t, lines[0], "PREDICATE TYPE")
	require.Contains(t, lines[0], "SIGNER IDENTITY")

	// Separator line
	require.Contains(t, lines[1], "---")

	// First data row has predicate type
	require.Contains(t, lines[2], "spdx.dev")

	// Third row (second identity for slsa) should not repeat predicate type
	// but should have the identity
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
