// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"errors"
	"fmt"
	"io"

	"github.com/carabiner-dev/attestation"
	ampelb "github.com/carabiner-dev/collector/envelope/bundle"
	"github.com/carabiner-dev/collector/statement/intoto"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sirupsen/logrus"
)

type Tool struct{}

func NewTool() *Tool {
	return &Tool{}
}

// Parse reades the budle data from reader r and decodes it into
func (t *Tool) ParseBundle(r io.Reader) (attestation.Envelope, error) {
	p := ampelb.Parser{}
	envelopeSet, err := p.ParseStream(r)
	if err != nil {
		return nil, fmt.Errorf("parsing bundle: %w", err)
	}
	if len(envelopeSet) == 0 {
		return nil, fmt.Errorf("no bundles could be extracted from input")
	}
	if len(envelopeSet) > 1 {
		logrus.Warnf("Input parse returned %d envelopes, only returning the first", len(envelopeSet))
	}
	return envelopeSet[0], nil
}

// getBundleContentIfDSSE returns the bundle contents if it is wrapped in a DSSE
// envelope. Returns nil in any other case.
func getBundleContentIfDSSE(bundle *protobundle.Bundle) *protobundle.Bundle_DsseEnvelope {
	if bundle.GetContent() == nil {
		return nil
	}
	if dsse, ok := bundle.GetContent().(*protobundle.Bundle_DsseEnvelope); ok {
		return dsse
	}

	return nil
}

// ExtractPredicateJSON is akin to ExtractPredicate but returns the predicated
// marshalled as JSON
func (t *Tool) ExtractPredicateJSON(envelope attestation.Envelope) ([]byte, error) {
	statement := envelope.GetStatement()
	if statement == nil {
		return nil, fmt.Errorf("no statement found in envelope")
	}

	pred := statement.GetPredicate()
	if pred == nil {
		return nil, errors.New("statement has no predicate")
	}

	return pred.GetData(), nil
}

// ExtractPredicateType returns a string with the attestation predicate type
func (t *Tool) ExtractPredicateType(bndl attestation.Envelope) (string, error) {
	if bndl.GetStatement() != nil {
		return bndl.GetStatement().GetType(), nil
	}
	return "", errors.New("bundle contains no statement")
}

// ExtractPredicate returns the attestation predicate data
func (t *Tool) ExtractPredicate(bndl attestation.Envelope) (attestation.Predicate, error) {
	if bndl.GetStatement() == nil {
		return nil, fmt.Errorf("bundle has no statement defined")
	}
	return bndl.GetStatement().GetPredicate(), nil
}

// ParseAttestation reads an attestation from the Reader r and
func (t *Tool) ParseAttestation(r io.Reader) (attestation.Statement, error) {
	p := intoto.Parser{}

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading attestation data")
	}
	statement, err := p.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parsing statement: %w", err)
	}
	return statement, nil
}

// ExtractAttestation returns a strut with the data decoded from the bundle
// contents JSON.
func (t *Tool) ExtractAttestation(bndl attestation.Envelope) (attestation.Statement, error) {
	return bndl.GetStatement(), nil
}

// ExtractAttestationJSON returns the attestation JSON enclosed in the bundle
func (t *Tool) ExtractAttestationJSON(bundle *protobundle.Bundle) ([]byte, error) {
	if bundle == nil {
		return nil, fmt.Errorf("attempt to extract predicate from nil bundle")
	}
	dssePayload := getBundleContentIfDSSE(bundle)
	if dssePayload == nil || dssePayload.DsseEnvelope == nil {
		return nil, fmt.Errorf("bundle has no DSSE payload")
	}

	return dssePayload.DsseEnvelope.GetPayload(), nil
}
