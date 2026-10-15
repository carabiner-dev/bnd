// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0
package cmd

import (
	"github.com/carabiner-dev/command/subject"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
)

// subjectsOptions wraps the shared subject options set for the commands
// that look attestations up by subject (get, ls). Files are hashed with
// sha256 only, as that is the digest the collectors index by.
type subjectsOptions struct {
	subject.Options
}

// getSubjects returns the subjects read from the command line as a slice
// of attestation.Subject structs.
func (so *subjectsOptions) getSubjects() ([]attestation.Subject, error) {
	so.Algorithms = []intoto.HashAlgorithm{intoto.AlgorithmSHA256}
	rds, err := so.ResourceDescriptors()
	if err != nil {
		return nil, err
	}
	ret := make([]attestation.Subject, 0, len(rds))
	for _, rd := range rds {
		ret = append(ret, rd)
	}
	return ret, nil
}
