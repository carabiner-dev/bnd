# 🥨 bnd

### A Utility to Work with Sigstore Bundles and Attestations

bnd is a utility that makes it easy to work with attestations and sigstore bundles.
It can create new bundles by "binding" an attestation and signing it. It can verify
existing bundles, extract data from them, inspect their contents and much more.

## Features

If you work with in-toto attestations, bnd is the perfect multitool for your daily
chores allowing you to:

- Sign in-toto statements or create them from bare predicates.
- Verify attestations wrapped in signed sigstore bundles.
- Pack and unpack attestations into/from linear json (jsonl) files.
- Push attestations to storage backends.
- Read, export and query attestation storage backends.
- List attestations with a compact summary of predicate types, signer identities and subjects.
- Inspect .jsonl files to view their contents.
- Attest data from files in git commits.
- Extract statements and predicates from sigstore bundles.
- Configure per-repository defaults via `.supplychain.yaml` (keys, collector repositories).

More information about each function can be found on each subcommand help screen.

## Usage

```
🥨 bnd: a utility to work with attestations and sigstore bundles.

bnd (pronounced bind) is a utility that makes it easy to work with attestations
and sigstore bundles. It can create new bundles by "binding" a statement, signing
it and wrapping it in a bundle. It can verify existing bundles, extract data
from them and inspect their contents.

Usage:
  bnd [command]

Examples:

Create a new bundle by signing and bundling an attestation and its verification
material:

  bnd statement --out=bundle.json statement.intoto.json

Inspect the resulting bundle:

  bnd inspect bundle.json

Extract the in-toto attestation from the bundle:

  bnd extract attestation bundle.json

Extract the predicate data from the bundle:

  bnd extract predicate bundle.json



Available Commands:
  commit      attest git commits
  completion  Generate the autocompletion script for the specified shell
  extract     extract data from sigstore bundles
  help        Help about any command
  inspect     prints useful information about a bundle
  ls          list attestations from source repositories
  pack        packs one or more bundles into a jsonl formatted file
  predicate   packs a new attestation into a bundle from a JSON predicate
  push        pushes an attestation or bundle to a repository
  read        read attestations from source repositories
  statement   binds an in-toto attestation in a signed bundle
  unpack      unpacks attestations bundled in a jsonl file
  verify      Verifies a bundle signature
  version     Prints the version

Flags:
  -h, --help               help for bnd
      --log-level string   the logging verbosity, either 'panic', 'fatal', 'error', 'warning', 'info', 'debug', 'trace' (default "info")
```

### Sign and Bundle an In-Toto Statement

To bind (sign + bundle) an attestation (also called a statement), use the
`bnd statement` subcommand.

```
> bnd statement test.intoto.json
Your browser will now be opened to:
https://oauth2.sigstore.dev/auth/auth?access_type=online&client_id=sigstore&code_challenge=7jBJObkVxlbMg-qUVlQvuGrHwXyAbwiSyD2DfEToUFo&code_challenge_method=S256&nonce=32FzQ9q24zGwpgPpLA0b0dyiYI6&redirect_uri=http%3A%2F%2Flocalhost%3A53697%2Fauth%2Fcallback&response_type=code&scope=openid+email&state=32FzQBCSlN3EIlb2JNiKM3rDyzl
{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial":{"certificate":{"rawBytes":"MIICzDCCAlOgAwIBAgIUX5fJbenOzRT9goKyXnFEcJ1LA70wCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjUwOTA1MDAxMTM2WhcNMjUwOTA1MDAyMTM2WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGE1B5YSAhibn5RQUa8rAS0LLGzkcu9RDDe4MQTp/fZo9NX/IZhDUt1Sp3VpOL+SoAztVVZB38bdichAsqgu+dKOCAXIwggFuMA4GA1UdDwEB/wQEAwIHgDATBgNVH
...
```

As shown above, when binding a statement, `bnd` opens the sigstore browser flow.
bnd has support for ambient credentials (GitHub actions for now) via [Carabiner's
signer library](https://github.com/carabiner-dev/signer).

### Listing Attestations

The `bnd ls` subcommand provides a compact summary of attestations from any
supported repository. It shows predicate types, signer identities and subjects
in a terminal-width-aware table:

```
> bnd ls jsonl:attestations.jsonl
PREDICATE TYPE             SIGNER IDENTITY            SUBJECT
------------------------   ------------------------   ------------------------
https://github.com/sl...   sigstore::.../heads/main   gitCommit:b12808f8c70...
https://slsa.dev/veri...   sigstore::.../heads/main   gitCommit:b12808f8c70...
https://slsa.dev/prov...   [unverified]               sha256:3d6e80bd0a359b...
```

When filtering by subject (`-s`) or predicate type (`--type`), the filtered
columns are removed from the table and their values are printed above it instead:

```
> bnd ls --type="https://spdx.dev/Document" jsonl:attestations.jsonl
Predicate type: https://spdx.dev/Document

SIGNER IDENTITY                          SUBJECT
--------------------------------------   --------------------------------------
[unverified]                             sha256:29599cb2a44f3275232bc5fc48d2...
```

### Inspecting JSONL Bundles

To view the contents of JSONL files, use the `bnd inspect` subcommand:

```
> bnd inspect attestations.jsonl

🔎  Bundle Details:
-------------------
Attestation #0
✉️  Envelope Media Type: application/vnd.dev.sigstore.bundle.v0.3+json
🔏 Signer identity: sigstore::https://token.actions.githubusercontent.com::https://github.com/carabiner-dev/demo-repo/.github/workflows/release.yaml@refs/tags/v0.0.1-pre29
📃 Attestation Details:
   Predicate Type: http://github.com/carabiner-dev/snappy/specs/branch-rules.yaml
   Attestation Subjects:
   - github.com/carabiner-dev/demo-repo@main
     sha256: 52e2da8f663cfb629f98dac2708106b139f851386a723faeba4dde373c24e844

Attestation #1
✉️  Envelope Media Type: application/vnd.dev.sigstore.bundle.v0.3+json
🔏 Signer identity: sigstore::https://token.actions.githubusercontent.com::https://github.com/carabiner-dev/demo-repo/.github/workflows/release.yaml@refs/tags/v0.0.1-pre29
📃 Attestation Details:
   Predicate Type: http://github.com/carabiner-dev/snappy/specs/mfa.yaml
   Attestation Subjects:
   - github.com/carabiner-dev
     sha256: 2775bba8b2170bef2f91b79d4f179fd87724ffee32b4a20b8304856fd3bf4b8f
...
```

## Supply Chain Configuration

bnd supports a per-repository `.supplychain.yaml` configuration file. When
present, it automatically provides default collector repositories and public
keys to all subcommands that accept them (`read`, `ls`, `inspect`).

```yaml
metadata:
    repositories:
        - jsonl:attestations.jsonl
        - github:owner/repo
keys:
    public:
        - path/to/key.pub
        - https://example.com/key.pub
        - |
          -----BEGIN PUBLIC KEY-----
          MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
          -----END PUBLIC KEY-----
```

The file is loaded automatically from the current directory. Use the
`--dotsupplychain` flag to specify an alternate path.

## Native Sigstore Signing

`bnd` implements sigstore keyless signing just as cosign does. It supports the
interactive and device flows as well as limited initial support for ambient
credentials (initially GitHub actions tokens).
