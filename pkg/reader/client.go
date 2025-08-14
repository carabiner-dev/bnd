// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package reader

import (
	"github.com/carabiner-dev/ampel/pkg/collector"
	"github.com/carabiner-dev/attestation"
)

type Client struct {
	impl clientImplementation
}

func New() *Client {
	return &Client{
		impl: &defaultClientImplementation{},
	}
}

func buildAgent() (*collector.Agent, error) {
	if err := collector.LoadDefaultRepositoryTypes(); err != nil {
		return nil, err
	}
	return collector.New()
}

// Fetch retrieves all the attestation from a source repository
func (c *Client) Fetch(uri string) ([]attestation.Envelope, error) {
	return c.impl.Fetch(uri)
}
