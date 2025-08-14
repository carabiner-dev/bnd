// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/carabiner-dev/ampel/pkg/formats/predicate"
	"github.com/carabiner-dev/ampel/pkg/formats/statement/intoto"
	"github.com/carabiner-dev/attestation"
	v1 "github.com/in-toto/attestation/go/v1"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/helpers"

	"github.com/carabiner-dev/bnd/internal/git"
)

// commitOptions
type commitOptions struct {
	predicateFileOptions
	signOptions
	outFileOptions
	sigstoreOptions
	CloneAddress     string
	repoURL          string
	repoPath         string
	clonePath        string
	Sha              string
	Tag              string
	PredicateGitPath string
	remoteNames      []string
}

// Validate checks the options
func (co *commitOptions) Validate() error {
	errs := []error{}
	errs = append(errs,
		co.signOptions.Validate(),
		co.predicateFileOptions.Validate(),
		co.outFileOptions.Validate(),
		co.sigstoreOptions.Validate(),
	)

	if co.Sha != "" && co.Tag != "" {
		errs = append(errs, errors.New("only tag or commit hash can be specified at the same time"))
	}

	if co.PredicatePath == "" && co.PredicateGitPath == "" {
		errs = append(errs, errors.New("no predicate file specified"))
	}

	if co.PredicatePath != "" && co.PredicateGitPath != "" {
		errs = append(errs, errors.New("predicater specified as local file and as data from the repo"))
	}

	if co.Tag != "" && (co.repoURL == "" && co.repoPath == "") {
		errs = append(errs, errors.New("repo URL or repo path must be sepcified whe attesting a git tag"))
	}

	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (co *commitOptions) AddFlags(cmd *cobra.Command) {
	co.signOptions.AddFlags(cmd)
	co.predicateFileOptions.AddFlags(cmd)
	co.outFileOptions.AddFlags(cmd)
	co.sigstoreOptions.AddFlags(cmd)

	cmd.PersistentFlags().StringVar(
		&co.Sha, "sha", "", "commit hash to attest (defaults to HEAD of main branch)",
	)

	cmd.PersistentFlags().StringVar(
		&co.Tag, "tag", "", "use a tag instead of a commit hash",
	)

	cmd.PersistentFlags().StringVarP(
		&co.CloneAddress, "repo", "r", "", "local path or url of the repository to clone",
	)

	cmd.PersistentFlags().StringVar(
		&co.PredicateGitPath, "predicate-git-path", "", "read the predicate from this path in the local repo",
	)
}

func addCommit(parentCmd *cobra.Command) {
	opts := &commitOptions{
		remoteNames: []string{"upstream", "origin"},
	}
	commitCmd := &cobra.Command{
		Short: "attest git commits",
		Long: fmt.Sprintf(`
🥨 %s commit

The commit subcommand generates statments about git commits. This lets
tools create attestations about the status of a repo at a point in time.

This is not intended to replace commit signing tools such as gittuf or
gitsign but rather to make it easy to associate predicates with a repository's
history.

The predicate data can be read from committed files or can be supplied externally.
The commit subcommmand can clone local or remote repositories. It can also
resolve tags, generating the correct subjects with their current hash.

Note that %s commit always clones the repo, even when operating on local 
repositories from disk. The purpose is to avoid messing up you environment as
the commit subcommand moves HEAD around.

	`, appname, appname),
		Use: "commit",
		Example: fmt.Sprintf(`
Create an attestation about the commit at HEAD, reading the predicate from data.json

  %s commit --repo=http://github.com/example/test --predicate=data.json

Attest to git tag v1 reading the predicate from data.json:

  %s commit --repo=http://github.com/example/test --tag=v1 --predicate=data.json

Create an attestation for tag v1, reading the predicate from a committed file:

  %s commit --repo=http://github.com/example/test --tag=v1 --predicate-git-path=pred.json

Same, but cloning the repo from a local clone:

  %s commit --repo myrepos/repo --tag=v1 --predicate-git-path=pred.json

`, appname, appname, appname, appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 && opts.PredicatePath != "" {
				opts.PredicatePath = args[0]
			}

			if len(args) > 0 && args[0] != opts.PredicatePath {
				return fmt.Errorf("predicate specified twice (-p and argument)")
			}

			// Detect if the clone address is a local path or a remote URL
			if helpers.Exists(opts.CloneAddress) {
				opts.repoPath = opts.CloneAddress
			} else {
				opts.repoURL = opts.CloneAddress
			}
			return nil
		},
		RunE: func(_ *cobra.Command, args []string) error {
			// Validate the options
			if err := opts.Validate(); err != nil {
				return err
			}

			logrus.Debugf("cloning %s", opts.CloneAddress)

			tmpPath, cleaner, err := git.CloneOrOpenCommit(opts.CloneAddress, opts.Sha)
			if err != nil {
				return fmt.Errorf("cloning remote repo: %w", err)
			}
			if tmpPath == "" {
				return errors.New("no repo path received from cloning operation")
			}
			defer cleaner()
			opts.clonePath = tmpPath

			// Use the predicate path from the options
			predicatePath := opts.PredicatePath

			//  ... unless its pointing to the cloned repo
			if opts.PredicateGitPath != "" {
				if opts.clonePath == "" {
					return errors.New("repo path not set")
				}
				predicatePath = path.Join(opts.clonePath, opts.PredicateGitPath)
			}

			f, err := os.Open(predicatePath)
			if err != nil {
				return fmt.Errorf("opening predicate file: %w", err)
			}

			predData, err := io.ReadAll(f)
			if err != nil {
				return fmt.Errorf("reading predicate data: %w", err)
			}

			// Convert if we're reading YAML
			if opts.ConvertYAML {
				predData, err = convertYaml(predData)
				if err != nil {
					return err
				}
			}

			optFn := []predicate.ParseOption{}
			if opts.PredicateType != "" {
				optFn = append(optFn, predicate.WithTypeHints(
					[]attestation.PredicateType{
						attestation.PredicateType(opts.PredicateType),
					}),
				)
			}
			pred, err := predicate.Parsers.Parse(predData, optFn...)
			if err != nil {
				return fmt.Errorf("parsing predicate data: %w", err)
			}

			// Create the new attestation
			statement := intoto.NewStatement(intoto.WithPredicate(pred))
			statement.Type = "https://in-toto.io/Statement/v1"
			statement.PredicateType = attestation.PredicateType(opts.PredicateType)

			head, err := git.GetHeadDetails(opts.clonePath)
			if err != nil {
				return fmt.Errorf("getting repo details: %w", err)
			}

			locator, err := makeVCSLocator(opts, head, git.GetRemotes)
			if err != nil {
				logrus.Errorf("error forming VCS locator: %v", err)
			}
			name := head.CommitSHA
			if head.Tag != "" {
				name = head.Tag
			}
			subject := &v1.ResourceDescriptor{
				Name:             name,
				Uri:              locator,
				DownloadLocation: locator,
				Digest: map[string]string{
					"sha1":      head.CommitSHA,
					"gitCommit": head.CommitSHA,
				},
			}

			statement.AddSubject(subject)

			// Marshal the attestation data
			attData, err := statement.ToJson()
			if err != nil {
				return fmt.Errorf("marshaling statement json: %w", err)
			}

			logrus.Debugf("ATTESTATION:\n%s\n/ATTESTATION\n", string(attData))

			signer := getSigner(&opts.sigstoreOptions, &opts.signOptions)

			bundle, err := signer.SignStatement(attData)
			if err != nil {
				return fmt.Errorf("writing signing statement: %w", err)
			}

			o, closer, err := opts.OutputWriter()
			if err != nil {
				return fmt.Errorf("getting output stream: %w", err)
			}
			defer closer()

			if err := signer.WriteBundle(bundle, o); err != nil {
				return err
			}
			return nil
		},
	}
	opts.AddFlags(commitCmd)
	parentCmd.AddCommand(commitCmd)
}

// makeVCSLocator builds the repository VCS locator from the available data
func makeVCSLocator(opts *commitOptions, head *git.HeadDetails, remoteReader func(string) (map[string]string, error)) (string, error) {
	sourceURL := ""
	if opts.repoURL != "" {
		sourceURL = opts.repoURL
	} else {
		remotes, err := remoteReader(opts.repoPath)
		if err != nil {
			return "", err
		}
		for _, k := range opts.remoteNames {
			if v, ok := remotes[k]; ok {
				sourceURL = v
				break
			}
		}

		// If no match, pick the first
		if sourceURL == "" {
			for _, v := range remotes {
				sourceURL = v
				break
			}
		}
	}

	// If the URL is on ssh, we need to make some changes
	if strings.Contains(sourceURL, "@") {
		_, u, _ := strings.Cut(sourceURL, "@")
		u = strings.Replace(u, ":", "/", 1)

		// if its a github url, remote the .git to make it more compact
		if strings.HasPrefix(u, "github.com/") {
			u = strings.TrimSuffix(u, ".git")
		}
		sourceURL = "ssh://" + u
	}

	u, err := url.Parse(sourceURL)
	if err != nil {
		return "", fmt.Errorf("parsing repo source URL")
	}

	return "git+" + u.String() + "@" + head.CommitSHA, nil
}
