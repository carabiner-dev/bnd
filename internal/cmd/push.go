// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/carabiner-dev/collector"
	"github.com/carabiner-dev/collector/envelope"
	"github.com/carabiner-dev/collector/repository/github"
	"github.com/spf13/cobra"
)

type pushOptions struct {
	Bundles []string
}

type pushGitHubOptions struct {
	pushOptions
	RepoName string
	RepoOrg  string
}

// Validate the options in context with arguments
func (o *pushOptions) Validate() error {
	if len(o.Bundles) == 0 {
		return errors.New("no bundles specified")
	}
	return nil
}

func (gho *pushGitHubOptions) Validate() error {
	errs := []error{}
	errs = append(errs, gho.pushOptions.Validate())
	if gho.RepoName == "" {
		errs = append(errs, errors.New("repository name not set"))
	}

	if gho.RepoOrg == "" {
		errs = append(errs, errors.New("repository organization not set"))
	}

	return errors.Join(errs...)
}

func (o *pushOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringSliceVarP(
		&o.Bundles,
		"bundle", "b", []string{}, "path to bundle",
	)
}

func (gho *pushGitHubOptions) AddFlags(cmd *cobra.Command) {
	gho.pushOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringVarP(
		&gho.RepoName,
		"repo", "r", "", "repository name",
	)

	cmd.PersistentFlags().StringVar(
		&gho.RepoOrg,
		"org", "", "repository organization",
	)
}

func addPush(parentCmd *cobra.Command) {
	pushCmd := &cobra.Command{
		Short: "pushes an attestation or bundle to a repository",
		Use:   "push",
	}
	addGitHubPush(pushCmd)
	parentCmd.AddCommand(pushCmd)
}

func addGitHubPush(parentCmd *cobra.Command) {
	opts := pushGitHubOptions{}
	pushCmd := &cobra.Command{
		Short: "pushes bundle to the GitHub attestation store",
		Long: fmt.Sprintf(`
🥨 %s push: Push attestations and bundles to the GitHub attestation store.

The push subcommand lets you send bundled attestations to remote storage
locations. Initial support is provided for the GitHub attestation store
but more drivers are on the way.

`, appname),
		Use:           "github [flags] [org/repo [bundle.json...]]",
		SilenceUsage:  false,
		SilenceErrors: true,
		Example: fmt.Sprintf(`
Push an attestation bundle to GitHub:

%s push github --bundle bundle.json --repo myorg --org repo

Same but with shortcut positional arguments:

%s push github myorg/repo bundle.json

`, appname, appname),
		PersistentPreRunE: initLogging,
		PreRunE: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 && opts.RepoName != "" && opts.RepoOrg != "" {
				if args[0] != fmt.Sprintf("%s/%s", opts.RepoOrg, opts.RepoName) {
					return fmt.Errorf("repo data specified twice (arg and flags)")
				}
			}

			if len(args) > 0 {
				org, name, did := strings.Cut(args[0], "/")
				if did {
					opts.RepoName = name
					opts.RepoOrg = org
				}
			}

			if len(args) > 1 {
				opts.Bundles = append(opts.Bundles, args[1:]...)
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}

			cmd.SilenceUsage = true

			repo, err := github.New(
				github.WithOwner(opts.RepoOrg), github.WithRepo(opts.RepoName),
			)
			if err != nil {
				return fmt.Errorf("creating collector repository: %w", err)
			}

			agent, err := collector.New(
				collector.WithRepository(repo),
			)
			if err != nil {
				return fmt.Errorf("creating collector agent: %w", err)
			}

			// Parse all envelopes
			envs, err := envelope.Parsers.ParseFiles(opts.Bundles)
			if err != nil {
				return fmt.Errorf("parsing envelopes: %w", err)
			}

			if err := agent.Store(cmd.Context(), envs); err != nil {
				return fmt.Errorf("storing envelopes: %w", err)
			}
			return nil
		},
	}
	opts.AddFlags(pushCmd)
	parentCmd.AddCommand(pushCmd)
}
