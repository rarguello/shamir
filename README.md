# Shamir's Secret Sharing CLI

[![Go CI](https://github.com/rarguello/shamir/actions/workflows/go.yml/badge.svg)](https://github.com/rarguello/shamir/actions/workflows/go.yml)
[![Release](https://github.com/rarguello/shamir/actions/workflows/release.yml/badge.svg)](https://github.com/rarguello/shamir/actions/workflows/release.yml)

A minimalist, secure, and self-contained command-line tool written in Go to split and reconstruct secrets using [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) (SSS).

## Features

- **Integrity-checked reconstruction:** Every secret is wrapped in a small envelope (magic bytes, version, and a SHA-256 digest) before being split, and the envelope is verified after combining. Mismatched, insufficient, or corrupted shares fail with an explicit error instead of silently returning garbage bytes that look like a valid secret. See [Integrity Envelope](#integrity-envelope) below.
- **Best-effort memory hygiene:** Secret, share, and envelope buffers are zeroed out after use. This reduces exposure but does not guarantee removal of all copies made by the Go runtime, the OS, pipes, or the shell.
- **Fully Static Binary:** Can be statically compiled with no external or dynamic library dependencies (ideal for offline, air-gapped environments).
- **UNIX Pipeline Compatible:** Reads raw secret bytes via stdin or a file, emits hex-encoded shares, and writes the reconstructed raw bytes to stdout — composes with standard tools like `split` and `cat`.

`Split` and `Combine` use the GF(256) implementation from [OpenBao](https://github.com/openbao/openbao)'s SDK (`github.com/openbao/openbao/sdk/v2/helper/shamir`) rather than a custom one. Polynomial coefficients are generated with `crypto/rand`.

## Static Compilation

To compile a fully static, standalone binary for Linux x86-64 with no dynamic library dependencies and stripped debugging symbols:

```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -o shamir .
```

## Usage

### 1. Split a Secret (`split`)

Splits a secret (read from standard input or a file) into $N$ shares, requiring a minimum threshold of $K$ shares to reconstruct.

**Flags:**
- `-shares` or `-n`: Total number of shares to create (2-255).
- `-threshold` or `-k`: Minimum number of shares required to reconstruct (2-255).
- `-file` or `-f`: Path to a file containing the secret (optional; reads from standard input if omitted).

#### Example (Split and distribute into individual files):

```bash
echo -n "MySuperSecretKey" | ./shamir split -shares 4 -threshold 3 | split -l 1 - share_
```
This generates files `share_aa`, `share_ab`, `share_ac`, and `share_ad`, each containing a single hex-encoded share.

### 2. Reconstruct a Secret (`combine`)

Reconstructs the original secret from the provided shares.

#### Reconstruct specifying individual files as arguments:
```bash
./shamir combine share_aa share_ac share_ad
```

#### Reconstruct by piping shares directly to standard input:
```bash
cat share_aa share_ac share_ad | ./shamir combine
```

## Integrity Envelope

Before splitting, the secret is wrapped as:

```
magic(4) || version(1) || secret(N) || SHA-256(magic || version || secret)(32)
```

Splitting operates on the wrapped envelope, not the raw secret, adding a fixed 37-byte overhead per share on top of Shamir's own 1-byte tag. Because the digest is split together with the secret, shares below the threshold reveal nothing about either one: Shamir's information-theoretic guarantee covers the whole envelope.

This detects wrong, insufficient, or corrupted shares with overwhelming probability. It does not authenticate the shares' provenance: a party who actively controls a threshold of shares could still substitute a different, self-consistent secret. That guarantee falls outside what Shamir's Secret Sharing alone provides, and would need an external, independently verified reference, such as a signed commitment recorded when the secret was split.

## Unit Tests

To execute the automated unit tests:
```bash
go test -v ./...
```
