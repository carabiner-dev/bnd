// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package supplychain

import (
	"fmt"

	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"

	v1 "github.com/carabiner-dev/bnd/internal/api/v1"
)

var _ command.OptionsSet = &Options{}

const (
	defaultDotSupplyChain = ".supplychain.yaml"
	flagIDDotSupplyChain  = "dotsupplychain"
)

// Options implements command.OptionsSet for the supplychain config file.
type Options struct {
	config          *command.OptionsSetConfig
	DotSupplyChain  string
	supplyChainConf *v1.SupplyChainConfig
}

// Config returns the flag configuration for the supplychain options.
func (o *Options) Config() *command.OptionsSetConfig {
	if o.config == nil {
		o.config = &command.OptionsSetConfig{
			Flags: map[string]command.FlagConfig{
				flagIDDotSupplyChain: {
					Long: "dotsupplychain",
					Help: "path to the .supplychain.yaml configuration file",
				},
			},
		}
	}
	return o.config
}

// AddFlags adds the supplychain flags to a command.
func (o *Options) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(
		&o.DotSupplyChain,
		o.Config().LongFlag(flagIDDotSupplyChain),
		defaultDotSupplyChain,
		o.Config().HelpText(flagIDDotSupplyChain),
	)
}

// Validate parses the supplychain config file. It must be called before
// GetSupplyChainConf.
func (o *Options) Validate() error {
	conf, err := Parse(o.DotSupplyChain)
	if err != nil {
		return fmt.Errorf("parsing supplychain config: %w", err)
	}
	o.supplyChainConf = conf
	return nil
}

// GetSupplyChainConf returns the parsed supply chain configuration.
// Validate must be called first.
func (o *Options) GetSupplyChainConf() *v1.SupplyChainConfig {
	return o.supplyChainConf
}
