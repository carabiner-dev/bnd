// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseBundles(t *testing.T) {
	t.Parallel()

	// A directory mixing a bundle and a jsonl file, plus a subdirectory
	// that must not be traversed.
	mixed := t.TempDir()
	copyTestFile(t, "testdata/single.bundle.json", filepath.Join(mixed, "single.bundle.json"))
	copyTestFile(t, "testdata/attestations.jsonl", filepath.Join(mixed, "attestations.jsonl"))
	require.NoError(t, os.MkdirAll(filepath.Join(mixed, "nested"), 0o750))
	copyTestFile(t, "testdata/single.bundle.json", filepath.Join(mixed, "nested", "ignored.bundle.json"))

	// A jsonl file with a line that is not JSON. The jsonl iterator skips
	// such lines, so the bundles around it are still parsed.
	garbage := filepath.Join(t.TempDir(), "garbage.jsonl")
	data, err := os.ReadFile("testdata/attestations.jsonl")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(garbage, append(data, []byte("not json\n")...), 0o600)) //nolint:gosec // test paths

	for _, tc := range []struct {
		name    string
		paths   []string
		count   int
		mustErr bool
	}{
		{"bundle", []string{"testdata/single.bundle.json"}, 1, false},
		{"jsonl", []string{"testdata/attestations.jsonl"}, 2, false},
		{"bundle-and-jsonl", []string{"testdata/single.bundle.json", "testdata/attestations.jsonl"}, 3, false},
		{"directory", []string{mixed}, 3, false},
		{"missing", []string{"testdata/does-not-exist.json"}, 0, true},
		{"jsonl-with-garbage-line", []string{garbage}, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			envs, err := parseBundles(tc.paths)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, envs, tc.count)
			for _, env := range envs {
				require.NotNil(t, env.GetStatement())
			}
		})
	}
}

func copyTestFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(dst, data, 0o600)) //nolint:gosec // test paths
}
