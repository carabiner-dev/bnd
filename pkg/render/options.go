// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package render

import "github.com/carabiner-dev/signer/key"

type Options struct {
	VerifySignatures bool
	PublicKeys       []key.PublicKeyProvider
}

var defaultOptions = Options{
	VerifySignatures: true,
	PublicKeys:       []key.PublicKeyProvider{},
}

type FnOpt func(opts *Options) error

func WithVerifySignatures(sino bool) FnOpt {
	return func(opts *Options) error {
		opts.VerifySignatures = sino
		return nil
	}
}

func WithPublicKey(ks ...key.PublicKeyProvider) FnOpt {
	return func(opts *Options) error {
		opts.PublicKeys = append(opts.PublicKeys, ks...)
		return nil
	}
}
