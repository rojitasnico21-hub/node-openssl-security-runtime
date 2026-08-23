# Patched Node Runtime Builder

This directory is a standalone, public-safe build candidate for a patched
Node.js runtime. It contains no application source and has no dependency on a
private repository, credentials, or deployment environment.

The recipe starts from the verified Node.js 22.23.2 source tarball, vendors
OpenSSL 3.5.7, applies only the audited CVE-2026-14456 security patch
adaptation, and regenerates OpenSSL headers with Node's canonical generator.

The intended certification contract is:

- Linux amd64 on ubuntu-24.04.
- Linux arm64 on ubuntu-24.04-arm.
- node --version is v22.23.2.
- process.versions.openssl remains truthfully 3.5.7.
- Patch provenance records OpenSSL commit
  08e7756c3900bcfd77a720e7b74e27d6e4ed01a9.
- Trivy v0.74.0 fails on any HIGH or CRITICAL finding. No ignore file, VEX,
  or threshold relaxation is used.

Dockerfile.builder is based on a digest-pinned official Node build image.
The Perl template module and NASM packages are downloaded by the workflow,
verified by SHA-256, and supplied to the builder as local inputs. No package
manager upgrade or CPAN installation is used.

The candidate is intentionally limited to runtime construction and
certification. It does not build an application image, publish artifacts,
create a repository, or contact a deployment host.

## Local shape

scripts/build-node.sh performs source verification, patch application,
canonical header generation, and the Node build. scripts/verify-runtime.sh
checks the resulting runtime and its provenance. The workflow is
github/workflows/certify.yml.

All URLs in the recipe are public upstream or Debian distribution URLs. The
workflow has read-only repository permissions and defines no secrets.
