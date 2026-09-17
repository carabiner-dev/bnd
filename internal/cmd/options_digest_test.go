// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStrongestDigest(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		digest map[string]string
		expect map[string]string
	}{
		{"empty", map[string]string{}, map[string]string{}},
		{"single", map[string]string{"sha1": "a"}, map[string]string{"sha1": "a"}},
		{"file-hashes", map[string]string{"sha256": "a", "sha512": "b"}, map[string]string{"sha512": "b"}},
		{"sha3-wins", map[string]string{"sha512": "a", "sha3_512": "b", "md5": "c"}, map[string]string{"sha3_512": "b"}},
		{"commit-keeps-sha1", map[string]string{"gitCommit": "a", "sha1": "a"}, map[string]string{"sha1": "a"}},
		{"known-over-unknown", map[string]string{"blake3": "a", "sha1": "b"}, map[string]string{"sha1": "b"}},
		{"unknowns-are-stable", map[string]string{"zzz": "a", "blake3": "b"}, map[string]string{"blake3": "b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.expect, strongestDigest(tc.digest))
		})
	}
}

func TestSingleDigestApplyToJSON(t *testing.T) {
	t.Parallel()
	in := []byte(`{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://example.com/v1",` +
		`"subject":[{"name":"commit","uri":"git+https://example.com/repo","digest":{"sha1":"abc","gitCommit":"abc"}},` +
		`{"name":"file","digest":{"sha256":"def","sha512":"ghi"}},{"name":"nodigest"}],"predicate":{"k":"v"}}`)

	// Off: the data is returned untouched
	out, err := (&singleDigestOptions{}).applyToJSON(in)
	require.NoError(t, err)
	require.Equal(t, in, out)

	out, err = (&singleDigestOptions{SingleSubject: true}).applyToJSON(in)
	require.NoError(t, err)
	var st struct {
		Type          string `json:"_type"`
		PredicateType string `json:"predicateType"`
		Subject       []struct {
			Name   string            `json:"name"`
			URI    string            `json:"uri"`
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
		Predicate map[string]string `json:"predicate"`
	}
	require.NoError(t, json.Unmarshal(out, &st))
	require.Equal(t, "https://in-toto.io/Statement/v1", st.Type)
	require.Equal(t, "https://example.com/v1", st.PredicateType)
	require.Equal(t, map[string]string{"k": "v"}, st.Predicate, "the predicate must survive untouched")
	require.Len(t, st.Subject, 3)
	require.Equal(t, map[string]string{"sha1": "abc"}, st.Subject[0].Digest)
	require.Equal(t, "git+https://example.com/repo", st.Subject[0].URI, "other subject fields must survive")
	require.Equal(t, map[string]string{"sha512": "ghi"}, st.Subject[1].Digest)
	require.Nil(t, st.Subject[2].Digest)

	_, err = (&singleDigestOptions{SingleSubject: true}).applyToJSON([]byte(`{"predicate":{}}`))
	require.Error(t, err, "a statement without subjects is rejected")
}
