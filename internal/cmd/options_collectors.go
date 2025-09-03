// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/carabiner-dev/collector"
	"github.com/spf13/cobra"
)

type collectorOptions struct {
	collectors []string
}

func (co *collectorOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringSliceVarP(
		&co.collectors, "collector", "c", []string{}, "attestation collector string",
	)
}

func (co *collectorOptions) Validate() error {
	return nil
}

// GetAgent returns a collector agent preloaded with the repositories
// defined in the options set. If there are no repos in the options, it
// returns an error.
func (co *collectorOptions) GetAgent() (*collector.Agent, error) {
	if err := collector.LoadDefaultRepositoryTypes(); err != nil {
		return nil, err
	}
	if len(co.collectors) == 0 {
		return nil, fmt.Errorf("no collector repositories defined")
	}

	agent, err := collector.New()
	if err != nil {
		return nil, err
	}

	for _, s := range co.collectors {
		if err := agent.AddRepositoryFromString(s); err != nil {
			return nil, err
		}
	}
	return agent, nil
}
