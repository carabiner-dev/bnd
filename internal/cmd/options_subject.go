// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0
package cmd

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/carabiner-dev/hasher"
	intoto "github.com/in-toto/attestation/go/v1"
	"sigs.k8s.io/release-utils/helpers"
)

type subjectsOptions struct {
	subjects []string
}

// getHashSet returns the hashsets
func (so *subjectsOptions) getHashSet() (hasher.FileHashSet, error) {
	return getSubjectHashes(so.subjects)
}

// getSubjectHash returns parses hashes passed as strings or computes the
// hashes of any strings that are files
func getSubjectHashes(hstrings []string) (hasher.FileHashSet, error) {
	res := hasher.FileHashSet{}
	if hashRegex == nil {
		hashRegex = regexp.MustCompile(hashRegexStr)
	}

	// If the string matches algo:hexValue then we never try to look
	// for a file. Never. So we first collect those that look like hashes
	possibleFiles := []string{}
	for _, hstring := range hstrings {
		pts := hashRegex.FindStringSubmatch(hstring)
		if pts == nil {
			possibleFiles = append(possibleFiles, hstring)
			continue
		}

		algo := strings.ToLower(pts[1])
		if _, ok := intoto.HashAlgorithms[algo]; !ok {
			return nil, errors.New("invalid hash algorithm in subject")
		}

		res[hstring] = *hasher.NewHashSet(map[string]string{algo: pts[2]})
	}

	// If it does not match, then check for a file
	for _, path := range possibleFiles {
		if !helpers.Exists(path) {
			return nil, fmt.Errorf("file %q not found", path)
		}
	}

	// Use the parallel hasher
	h := hasher.New()
	h.Options.Algorithms = []intoto.HashAlgorithm{intoto.AlgorithmSHA256}
	hashSet, err := h.HashFiles(possibleFiles)
	if err != nil {
		return nil, fmt.Errorf("hashing files: %w", err)
	}
	for path, hSet := range *hashSet {
		res[path] = hSet
	}

	return res, nil
}
