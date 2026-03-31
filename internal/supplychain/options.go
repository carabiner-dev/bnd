// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package supplychain

import (
	"fmt"
	"os"

	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"

	v1 "github.com/carabiner-dev/bnd/internal/api/v1"
)

var _ command.OptionsSet = &Options{}

const (
	defaultDotSupplyChain     = ".supplychain.yaml"
	flagIDDotSupplyChain      = "dotsupplychain"
	flagIDForceDotSupplyChain = "dotsupplychain-force"
)

// Options implements command.OptionsSet for the supplychain config file.
type Options struct {
	config              *command.OptionsSetConfig
	DotSupplyChain      string
	ForceDotSupplyChain bool
	supplyChainConf     *v1.SupplyChainConfig
}

// Config returns the flag configuration for the supplychain options.
func (o *Options) Config() *command.OptionsSetConfig {
	if o.config == nil {
		o.config = &command.OptionsSetConfig{
			Flags: map[string]command.FlagConfig{
				flagIDDotSupplyChain: {
					Long: "dotsupplychain",
					Help: "path to the .supplychain.yaml configuration file (set to empty to disable)",
				},
				flagIDForceDotSupplyChain: {
					Long: "dotsupplychain-force",
					Help: "always merge .supplychain.yaml collectors even when specified on the command line",
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
	cmd.PersistentFlags().BoolVar(
		&o.ForceDotSupplyChain,
		o.Config().LongFlag(flagIDForceDotSupplyChain),
		false,
		o.Config().HelpText(flagIDForceDotSupplyChain),
	)
}

// Validate parses the supplychain config file. It must be called before
// GetSupplyChainConf.
func (o *Options) Validate() error {
	if o.DotSupplyChain == "" {
		return nil
	}

	conf, err := Parse(o.DotSupplyChain)
	if err != nil {
		return fmt.Errorf("parsing supplychain config: %w", err)
	}

	if conf == nil && o.ForceDotSupplyChain {
		fmt.Fprintf(os.Stderr, "Warning: --%s set but %q was not found\n", flagIDForceDotSupplyChain, o.DotSupplyChain)
	}

	o.supplyChainConf = conf
	return nil
}

// GetSupplyChainConf returns the parsed supply chain configuration.
// Validate must be called first.
func (o *Options) GetSupplyChainConf() *v1.SupplyChainConfig {
	return o.supplyChainConf
}

// ShouldUseConfig determines whether the supply chain configuration should be
// applied given whether collectors were specified on the command line. It
// returns whether to use the config and an optional notice message to display
// to the user (empty string means no notice).
func (o *Options) ShouldUseConfig(hasCliCollectors bool) (useConfig bool, notice string) {
	if o.supplyChainConf == nil {
		return false, ""
	}

	if o.ForceDotSupplyChain {
		return true, ""
	}

	if hasCliCollectors {
		return false, fmt.Sprintf(
			"Notice: %s found but not used because collectors were specified on the command line. Use --%s to override.",
			o.DotSupplyChain, flagIDForceDotSupplyChain,
		)
	}

	return true, ""
}
