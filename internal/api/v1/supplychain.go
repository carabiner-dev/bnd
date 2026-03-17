// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"errors"
	"fmt"
	"net/url"
	"os"

	"github.com/carabiner-dev/signer/key"
	"sigs.k8s.io/release-utils/http"
)

// GetPublicKeys resolves all public key entries in the supply chain config
// and returns them as key providers. Each entry can be:
//   - inline key data (PEM or GPG armored)
//   - a local file path
//   - a URL to fetch remotely
//
// Remote URLs are fetched in parallel.
func (c *SupplyChainConfig) GetPublicKeys() ([]key.PublicKeyProvider, error) {
	if c.GetKeys() == nil {
		return nil, nil
	}

	entries := c.GetKeys().GetPublic()
	if len(entries) == 0 {
		return nil, nil
	}

	// Classify each entry as inline data, file path, or URL.
	var (
		urlEntries  []string
		urlIndicies []int
		keyData     = make([][]byte, len(entries))
	)

	for i, entry := range entries {
		switch {
		case isURL(entry):
			urlEntries = append(urlEntries, entry)
			urlIndicies = append(urlIndicies, i)
		case isFile(entry):
			data, err := os.ReadFile(entry)
			if err != nil {
				return nil, fmt.Errorf("reading key file %q: %w", entry, err)
			}
			keyData[i] = data
		default:
			// Treat as inline key data
			keyData[i] = []byte(entry)
		}
	}

	// Fetch all remote keys in parallel
	if len(urlEntries) > 0 {
		agent := http.NewAgent()
		results, errs := agent.GetGroup(urlEntries)
		if err := errors.Join(errs...); err != nil {
			return nil, fmt.Errorf("fetching remote keys: %w", err)
		}
		for j, idx := range urlIndicies {
			keyData[idx] = results[j]
		}
	}

	// Parse all key data into providers
	parser := key.NewParser()
	var providers []key.PublicKeyProvider
	for i, data := range keyData {
		if len(data) == 0 {
			return nil, fmt.Errorf("empty key data for entry %d (%q)", i, entries[i])
		}
		provider, err := parser.ParsePublicKeyProvider(data)
		if err != nil {
			return nil, fmt.Errorf("parsing key %q: %w", entries[i], err)
		}
		providers = append(providers, provider)
	}

	return providers, nil
}

// isURL returns true if the string looks like an HTTP(S) URL.
func isURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

// isFile returns true if the path exists on disk.
func isFile(s string) bool {
	info, err := os.Stat(s)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
