// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package supplychain

import (
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	v1 "github.com/carabiner-dev/bnd/internal/api/v1"
)

// yamlConfig is the intermediary struct for YAML unmarshaling. Proto-generated
// structs lack YAML tags so we unmarshal into this and convert to proto.
type yamlConfig struct {
	Metadata struct {
		Repositories []string `yaml:"repositories"`
	} `yaml:"metadata"`
	Keys struct {
		Public []string `yaml:"public"`
	} `yaml:"keys"`
}

// toProto converts the YAML intermediary to the proto message.
func (yc *yamlConfig) toProto() *v1.SupplyChainConfig {
	return &v1.SupplyChainConfig{
		Metadata: &v1.Metadata{Repositories: yc.Metadata.Repositories},
		Keys:     &v1.Keys{Public: yc.Keys.Public},
	}
}

// Parse reads a supplychain config from the given path. If the file is not
// found at the exact path, it tries swapping the extension between .yaml
// and .yml before returning an error.
func Parse(path string) (*v1.SupplyChainConfig, error) {
	for _, candidate := range resolvePaths(path) {
		f, err := os.Open(candidate)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("opening %s: %w", candidate, err)
		}
		defer f.Close() //nolint:errcheck

		conf, err := ParseReader(f)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", candidate, err)
		}
		return conf, nil
	}

	// No config file found — this is not an error, it's optional.
	return nil, nil
}

// ParseReader reads a supplychain config from an io.Reader.
func ParseReader(r io.Reader) (*v1.SupplyChainConfig, error) {
	var yc yamlConfig
	if err := yaml.NewDecoder(r).Decode(&yc); err != nil {
		return nil, fmt.Errorf("decoding YAML: %w", err)
	}
	return yc.toProto(), nil
}

// resolvePaths returns a list of candidate file paths to try. The exact
// path is always tried first. If it ends in .yaml, the .yml variant is
// tried next and vice versa.
func resolvePaths(path string) []string {
	switch {
	case strings.HasSuffix(path, ".yaml"):
		return []string{
			path,
			strings.TrimSuffix(path, ".yaml") + ".yml",
		}
	case strings.HasSuffix(path, ".yml"):
		return []string{
			path,
			strings.TrimSuffix(path, ".yml") + ".yaml",
		}
	default:
		return []string{path}
	}
}
