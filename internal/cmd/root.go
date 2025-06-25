// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/log"
	"sigs.k8s.io/release-utils/version"

	"github.com/carabiner-dev/bnd/pkg/bnd"
)

const appname = "bnd"

var rootCmd = &cobra.Command{
	Short: fmt.Sprintf("%s: a utility to work with sigstore bundles", appname),
	Long: fmt.Sprintf(`
🥨 %s: a utility to work with attestations and sigstore bundles.
	
bnd (pronounced bind) is a utility that makes it easy to work with attestations
and sigstore bundles. It can create new bundles by "binding" a sattement, signing
it and wrappring it in a bundle. It can verify existing bundles, extract data
from them and inspect their contents.

`, appname),
	Use:               appname,
	SilenceUsage:      false,
	PersistentPreRunE: initLogging,
	Example: fmt.Sprintf(`
Create a new bundle by signing and bundling an attestation and its verification
material:

  %s statement --out=bundle.json statement.intoto.json

Inspect the resulting bundle:

  %s inspect bundle.json

Extract the in-toto attestation from the bundle:

  %s extract attestation bundle.json

Extract the predicate data from the bundle:

  %s extract predicate bundle.json

	`, appname, appname, appname, appname),
}

type commandLineOptions struct {
	logLevel string
}

var commandLineOpts = commandLineOptions{}

func initLogging(*cobra.Command, []string) error {
	return log.SetupGlobalLogger(commandLineOpts.logLevel)
}

// Execute builds the command
func Execute() {
	rootCmd.PersistentFlags().StringVar(
		&commandLineOpts.logLevel,
		"log-level", "info", fmt.Sprintf("the logging verbosity, either %s", log.LevelNames()),
	)
	addStatement(rootCmd)
	addPredicate(rootCmd)
	addExtract(rootCmd)
	addInspect(rootCmd)
	addVerify(rootCmd)
	addPush(rootCmd)
	addPack(rootCmd)
	addUnpack(rootCmd)
	addCommit(rootCmd)
	addRead(rootCmd)
	rootCmd.AddCommand(version.WithFont("doom"))

	if err := rootCmd.Execute(); err != nil {
		logrus.Fatal(err)
	}
}

// getSigner builds a bnd signer from a sigstore options set
func getSigner(opts *sigstoreOptions, sopts *signOptions) *bnd.Signer {
	signer := bnd.NewSigner()
	signer.Options.TufRootPath = opts.TufRootPath
	signer.Options.TufRootURL = opts.TufRootURL
	signer.Options.OidcClientID = sopts.OidcClientID
	signer.Options.OidcIssuer = sopts.OidcIssuer
	signer.Options.OidcRedirectURL = sopts.OidcRedirectURL

	return signer
}
