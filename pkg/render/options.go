// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package render

type Options struct {
	VerifySignatures bool
}

var defaultOptions = Options{
	VerifySignatures: true,
}

type FnOpt func(opts *Options) error

func WithVerifySignatures(sino bool) FnOpt {
	return func(opts *Options) error {
		opts.VerifySignatures = sino
		return nil
	}
}
