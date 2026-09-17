// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/carabiner-dev/collector/statement/intoto"
	"github.com/spf13/cobra"
)

// digestStrength ranks the digest algorithms in-toto defines, strongest
// first. sha1 ranks above gitCommit: both are the same hash of a commit
// but sha1 is the algorithm the rest of the tooling keys subjects on.
// Algorithms not listed rank below all of these.
var digestStrength = []string{
	"sha3_512", "sha512", "sha3_384", "sha384", "sha512_256", "sha3_256", "sha256",
	"sha512_224", "sha3_224", "sha224", algoSHA1, algoGitCommit, "gitTag", "gitTree",
	"gitBlob", "dirHash", "md5",
}

// Digest algorithm names used across the commands
const (
	algoSHA1      = "sha1"
	algoGitCommit = "gitCommit"
)

// singleDigestOptions adds the --single-subject flag to commands that
// produce statements.
type singleDigestOptions struct {
	SingleSubject bool
}

// AddFlags adds the flag to a cobra command
func (o *singleDigestOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVar(
		&o.SingleSubject, "single-subject", false,
		"keep only the strongest digest of each subject (some stores, like GitHub's, accept a single digest per subject)",
	)
}

// applyToStatement reduces the subjects of statement to one digest each
// when the flag is set.
func (o *singleDigestOptions) applyToStatement(statement *intoto.Statement) {
	if !o.SingleSubject {
		return
	}
	for _, subject := range statement.Subject {
		subject.Digest = strongestDigest(subject.GetDigest())
	}
}

// applyToJSON reduces the subjects in the serialized statement data to one
// digest each when the flag is set. The statement is edited as generic
// JSON so fields this tool does not know survive untouched.
func (o *singleDigestOptions) applyToJSON(data []byte) ([]byte, error) {
	if !o.SingleSubject {
		return data, nil
	}
	statement := map[string]any{}
	if err := json.Unmarshal(data, &statement); err != nil {
		return nil, fmt.Errorf("parsing statement: %w", err)
	}
	subjects, ok := statement["subject"].([]any)
	if !ok {
		return nil, fmt.Errorf("statement has no subject list")
	}
	for _, s := range subjects {
		subject, ok := s.(map[string]any)
		if !ok {
			continue
		}
		rawDigest, ok := subject["digest"].(map[string]any)
		if !ok {
			continue
		}
		digest := make(map[string]string, len(rawDigest))
		for algo, v := range rawDigest {
			value, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("digest %q of a subject is not a string", algo)
			}
			digest[algo] = value
		}
		subject["digest"] = strongestDigest(digest)
	}
	return json.Marshal(statement)
}

// strongestDigest returns digest reduced to the entry of its strongest
// algorithm, the highest ranked in digestStrength. Unknown algorithms
// come last, ordered by name so the result is stable. A digest with one
// entry or none is returned as is.
func strongestDigest(digest map[string]string) map[string]string {
	if len(digest) < 2 {
		return digest
	}
	rank := func(algo string) int {
		if i := slices.Index(digestStrength, algo); i >= 0 {
			return i
		}
		return len(digestStrength)
	}
	best := ""
	for algo := range digest {
		if best == "" || rank(algo) < rank(best) || (rank(algo) == rank(best) && algo < best) {
			best = algo
		}
	}
	return map[string]string{best: digest[best]}
}
