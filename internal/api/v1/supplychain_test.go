// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// testECDSAPEM is a valid ECDSA P-256 public key for testing.
const testECDSAPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElK5oxg8KfI+1y9o/d8oo/ieuIsnB
foKW4oX/JO8ptyp6pQW89f7/AywFvzG+7qg5Fq+vTTIRcpw1CED3eBXFVw==
-----END PUBLIC KEY-----`

func TestGetPublicKeys_Nil(t *testing.T) {
	t.Parallel()
	conf := &SupplyChainConfig{}
	keys, err := conf.GetPublicKeys()
	require.NoError(t, err)
	require.Nil(t, keys)
}

func TestGetPublicKeys_Empty(t *testing.T) {
	t.Parallel()
	conf := &SupplyChainConfig{
		Keys: &Keys{Public: []string{}},
	}
	keys, err := conf.GetPublicKeys()
	require.NoError(t, err)
	require.Nil(t, keys)
}

func TestGetPublicKeys_InlineKey(t *testing.T) {
	t.Parallel()
	conf := &SupplyChainConfig{
		Keys: &Keys{Public: []string{testECDSAPEM}},
	}
	keys, err := conf.GetPublicKeys()
	require.NoError(t, err)
	require.Len(t, keys, 1)
}

func TestGetPublicKeys_FileKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.pub")
	require.NoError(t, os.WriteFile(keyPath, []byte(testECDSAPEM), 0o600))

	conf := &SupplyChainConfig{
		Keys: &Keys{Public: []string{keyPath}},
	}
	keys, err := conf.GetPublicKeys()
	require.NoError(t, err)
	require.Len(t, keys, 1)
}

func TestGetPublicKeys_URLKey(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, testECDSAPEM) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	conf := &SupplyChainConfig{
		Keys: &Keys{Public: []string{srv.URL + "/key.pub"}},
	}
	keys, err := conf.GetPublicKeys()
	require.NoError(t, err)
	require.Len(t, keys, 1)
}

func TestGetPublicKeys_Mixed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.pub")
	require.NoError(t, os.WriteFile(keyPath, []byte(testECDSAPEM), 0o600))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, testECDSAPEM) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	conf := &SupplyChainConfig{
		Keys: &Keys{Public: []string{
			testECDSAPEM,                // inline
			keyPath,                     // file
			srv.URL + "/remote-key.pub", // URL
		}},
	}
	keys, err := conf.GetPublicKeys()
	require.NoError(t, err)
	require.Len(t, keys, 3)
}

func TestGetPublicKeys_InvalidInlineData(t *testing.T) {
	t.Parallel()
	conf := &SupplyChainConfig{
		Keys: &Keys{Public: []string{"not-valid-key-data"}},
	}
	_, err := conf.GetPublicKeys()
	require.Error(t, err)
}

func TestGetPublicKeys_URLFetchError(t *testing.T) {
	t.Parallel()
	conf := &SupplyChainConfig{
		Keys: &Keys{Public: []string{"https://127.0.0.1:1/nonexistent"}},
	}
	_, err := conf.GetPublicKeys()
	require.Error(t, err)
}

func TestIsURL(t *testing.T) {
	t.Parallel()
	require.True(t, isURL("https://example.com/key.pub"))
	require.True(t, isURL("http://example.com/key.pub"))
	require.False(t, isURL("/path/to/key"))
	require.False(t, isURL("-----BEGIN PUBLIC KEY-----"))
	require.False(t, isURL("relative/path"))
}

func TestIsFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "exists.txt")
	require.NoError(t, os.WriteFile(path, []byte("data"), 0o600))

	require.True(t, isFile(path))
	require.False(t, isFile(filepath.Join(dir, "nope.txt")))
	require.False(t, isFile(dir))
}
