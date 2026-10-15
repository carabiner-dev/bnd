// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0
package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSubjectsOptionsGetSubjects(t *testing.T) {
	t.Parallel()
	const sha1Hex = "16bc446f94bcef9093785f81897d2cfcbbcbe238"
	file := filepath.Join(t.TempDir(), "hello.txt")
	require.NoError(t, os.WriteFile(file, []byte("hello\n"), 0o600))

	so := &subjectsOptions{}
	so.Subjects = []string{"gitCommit:" + sha1Hex, "SHA1:" + sha1Hex, file}
	subs, err := so.getSubjects()
	require.NoError(t, err)
	require.Len(t, subs, 3)
	require.Equal(t, map[string]string{"gitCommit": sha1Hex}, subs[0].GetDigest())
	require.Equal(t, map[string]string{"sha1": sha1Hex}, subs[1].GetDigest())
	require.Equal(t, map[string]string{
		"sha256": "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
	}, subs[2].GetDigest())

	so.Subjects = []string{"sha256:abc"}
	_, err = so.getSubjects()
	require.Error(t, err)
}
