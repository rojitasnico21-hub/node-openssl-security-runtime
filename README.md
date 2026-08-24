# Node OpenSSL Security Runtime

This is a standalone, public builder and certification policy for an
independent custom Node.js runtime. It contains no application source and has
no dependency on a private repository, credentials, or deployment
environment. Original builder code is licensed under Apache-2.0; Node.js and
OpenSSL remain separately licensed upstream components.

The recipe starts from the verified Node.js 22.23.2 source tarball, vendors
OpenSSL 3.5.7, applies only the audited CVE-2026-14456 security patch
adaptation, and regenerates OpenSSL headers with Node's canonical generator.

The certification contract is intentionally fail-closed:

- Linux amd64 on ubuntu-24.04.
- Linux arm64 on ubuntu-24.04-arm.
- node --version is v22.23.2.
- process.versions.openssl remains truthfully 3.5.7.
- Patch provenance records OpenSSL commit
  08e7756c3900bcfd77a720e7b74e27d6e4ed01a9.
- Every public input, the official/adapted patch relationship, Dockerfile
  frontend, Buildx executable, BuildKit image, Node build-base index, and
  architecture mapping is pinned and verified by `BUILD_MANIFEST.json`.
- A baseline OpenSSL 3.5.7 negative control must fail the pending-QUIC
  capacity contract, and the patched Node OpenSSL archive must pass it with
  default capacity 256. This is the authoritative patch proof; Trivy is
  defense in depth and cannot by itself prove a statically embedded fix.
- Trivy v0.74.0 uses a verified binary, retains its DB metadata, creates an
  SBOM and JSON report, and fails on any HIGH or CRITICAL finding. No ignore
  file, VEX, `--ignore-unfixed`, or threshold relaxation is used.
- Only a `workflow_dispatch` from this repository's trusted `main` ref can
  create a success-only, architecture-bound runtime package. Failed jobs can
  upload diagnostic evidence but never a package named certified.

`Dockerfile.builder` is based on a digest-pinned official Node build image.
The Perl template module and NASM packages are downloaded by the workflow,
verified by SHA-256, and supplied to the builder as local inputs. No package
manager upgrade or CPAN installation is used.

The runtime package uses the stable layout `/nodejs/bin/node` plus
`/evidence/` and `/licenses/`. The intended future OCI is built from a
digest-pinned `distroless/base-nossl-debian12` base, contains exactly that
custom Node binary, and rejects any external `libssl` or `libcrypto` runtime
dependency. A separate `publish.yml` models a least-privilege, trusted-main
promotion boundary; it is deliberately disabled pending a separately reviewed
publication change, so certification itself cannot publish an OCI image or a
release asset.

`licenses/Node-LICENSE`, `licenses/OpenSSL-LICENSE.txt`, and
`licenses/MODIFICATION-NOTICE.md` must accompany every runtime package. The
notice identifies the CVE backport and explains the documentation-only
Node-vendoring adaptation. The runtime does not claim to be an official
Node.js binary.

## Local shape

scripts/build-node.sh performs source verification, patch application,
canonical header generation, and the Node build. scripts/verify-runtime.sh
checks the resulting runtime and its provenance. The workflow is
github/workflows/certify.yml.

All URLs in the recipe are public upstream or Debian distribution URLs. The
certification workflow has read-only repository permissions and defines no
secrets. The promotion workflow scopes package, OIDC, attestation, and release
permissions only to its separately gated promotion job.
