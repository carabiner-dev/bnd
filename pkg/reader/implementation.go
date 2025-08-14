// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package reader

import (
	"context"
	"fmt"

	"github.com/carabiner-dev/attestation"
)

type clientImplementation interface {
	Fetch(string) ([]attestation.Envelope, error)
}

type defaultClientImplementation struct{}

func (impl *defaultClientImplementation) Fetch(uri string) ([]attestation.Envelope, error) {
	agent, err := buildAgent()
	if err != nil {
		return nil, fmt.Errorf("creating new collector agent: %w", err)
	}
	if err := agent.AddRepositoryFromString(uri); err != nil {
		return nil, fmt.Errorf("adding new repository: %w", err)
	}

	return agent.Fetch(context.Background())
}
