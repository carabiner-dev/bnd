// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package supplychain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const validYAML = `---
metadata:
    repositories:
        - jsonl:test-slsa-source.jsonl
        - coci:registry.access.redhat.com/ubi10/ubi-minimal:latest
keys:
    public:
        - "----BEGIN...."
        - https://example.com/key.pub
        - path/to/key
`

func TestParseReader(t *testing.T) {
	t.Parallel()
	conf, err := ParseReader(strings.NewReader(validYAML))
	require.NoError(t, err)
	require.NotNil(t, conf)
	require.NotNil(t, conf.GetMetadata())
	require.NotNil(t, conf.GetKeys())

	require.Equal(t, []string{
		"jsonl:test-slsa-source.jsonl",
		"coci:registry.access.redhat.com/ubi10/ubi-minimal:latest",
	}, conf.GetMetadata().GetRepositories())

	require.Equal(t, []string{
		"----BEGIN....",
		"https://example.com/key.pub",
		"path/to/key",
	}, conf.GetKeys().GetPublic())
}

func TestParseReader_Empty(t *testing.T) {
	t.Parallel()
	conf, err := ParseReader(strings.NewReader("---\n"))
	require.NoError(t, err)
	require.NotNil(t, conf)
	require.Empty(t, conf.GetMetadata().GetRepositories())
	require.Empty(t, conf.GetKeys().GetPublic())
}

func TestParseReader_Invalid(t *testing.T) {
	t.Parallel()
	_, err := ParseReader(strings.NewReader("not: [valid: yaml"))
	require.Error(t, err)
}

func TestParse_YAMLExtension(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, ".supplychain.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validYAML), 0o600))

	conf, err := Parse(path)
	require.NoError(t, err)
	require.Len(t, conf.GetMetadata().GetRepositories(), 2)
	require.Len(t, conf.GetKeys().GetPublic(), 3)
}

func TestParse_YMLFallback(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Write only a .yml file, request the .yaml path
	ymlPath := filepath.Join(dir, ".supplychain.yml")
	require.NoError(t, os.WriteFile(ymlPath, []byte(validYAML), 0o600))

	yamlPath := filepath.Join(dir, ".supplychain.yaml")
	conf, err := Parse(yamlPath)
	require.NoError(t, err)
	require.Len(t, conf.GetMetadata().GetRepositories(), 2)
}

func TestParse_YAMLFallbackFromYML(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Write only a .yaml file, request the .yml path
	yamlPath := filepath.Join(dir, ".supplychain.yaml")
	require.NoError(t, os.WriteFile(yamlPath, []byte(validYAML), 0o600))

	ymlPath := filepath.Join(dir, ".supplychain.yml")
	conf, err := Parse(ymlPath)
	require.NoError(t, err)
	require.Len(t, conf.GetMetadata().GetRepositories(), 2)
}

func TestParse_NotFound(t *testing.T) {
	t.Parallel()
	conf, err := Parse(filepath.Join(t.TempDir(), ".supplychain.yaml"))
	require.NoError(t, err)
	require.Nil(t, conf)
}

func TestResolvePaths(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		path string
		want []string
	}{
		{"yaml-ext", ".supplychain.yaml", []string{".supplychain.yaml", ".supplychain.yml"}},
		{"yml-ext", ".supplychain.yml", []string{".supplychain.yml", ".supplychain.yaml"}},
		{"no-ext", "config", []string{"config"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, resolvePaths(tt.path))
		})
	}
}
