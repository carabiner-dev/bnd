// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"fmt"
	"slices"

	v1 "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/collector/statement/intoto"
	"github.com/spf13/cobra"
)

// digestStrength ranks the digest algorithms in-toto defines, strongest
// first. sha1 ranks above gitCommit: both are the same hash of a commit
// but sha1 is the algorithm the rest of the tooling keys subjects on.
// Algorithms not listed rank below all of these.
var digestStrength = []string{
	algoSHA3_512, algoSHA512, algoSHA3_384, algoSHA384, algoSHA512_256, algoSHA3_256,
	algoSHA256, algoSHA512_224, algoSHA3_224, algoSHA224, algoSHA1, algoGitCommit,
	algoGitTag, algoGitTree, algoGitBlob, algoDirHash, algoMD5,
}

// Digest algorithm names used across the commands. These are taken from the
// in-toto constants so the spelling cannot drift from what attestations
// actually carry.
const (
	algoMD5        = string(v1.AlgorithmMD5)
	algoSHA1       = string(v1.AlgorithmSHA1)
	algoSHA224     = string(v1.AlgorithmSHA224)
	algoSHA512_224 = string(v1.AlgorithmSHA512_224)
	algoSHA256     = string(v1.AlgorithmSHA256)
	algoSHA512_256 = string(v1.AlgorithmSHA512_256)
	algoSHA384     = string(v1.AlgorithmSHA384)
	algoSHA512     = string(v1.AlgorithmSHA512)
	algoSHA3_224   = string(v1.AlgorithmSHA3_224)
	algoSHA3_256   = string(v1.AlgorithmSHA3_256)
	algoSHA3_384   = string(v1.AlgorithmSHA3_384)
	algoSHA3_512   = string(v1.AlgorithmSHA3_512)
	algoGitBlob    = string(v1.AlgorithmGitBlob)
	algoGitCommit  = string(v1.AlgorithmGitCommit)
	algoGitTag     = string(v1.AlgorithmGitTag)
	algoGitTree    = string(v1.AlgorithmGitTree)
	algoDirHash    = string(v1.AlgorithmDirHash)
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
