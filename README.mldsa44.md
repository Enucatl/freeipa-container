# ML-DSA-44 FreeIPA image

This branch adds a small compatibility patch to the pinned upstream AlmaLinux 10
image so FreeIPA can use externally issued ML-DSA-44 certificates without a
Dogtag CA. It keeps the upstream package versions and certificate chain
validation. It does not install dependencies or create a certificate authority.

The patch reads a certificate's SubjectPublicKeyInfo using FreeIPA's existing
ASN.1 parser. HTTP certificate import uses the installed OpenSSL to extract the
PKCS#12 certificate and key, verifies their public keys match, and writes the
encrypted HTTP private key with mode `0600`. These paths avoid unsupported
ML-DSA key objects in the bundled Python cryptography package.

Base image:

```text
docker.io/freeipa/freeipa-server:almalinux-10@sha256:811ca9aad63e2529d0f983e616e11717ac012cb2da186a0e6b44b3e07d18ad85
```

The upstream container source revision is
`18d5afba9e993c20fde0b33d50903b8b439df3cc`.

Build and run the focused compatibility check:

```bash
docker build -f Dockerfile.mldsa -t localhost/freeipa-server:mldsa44 .
docker run --rm --network none --hostname ipa.home.arpa --add-host ipa.home.arpa:127.0.0.2 --entrypoint python3 localhost/freeipa-server:mldsa44 /usr/local/libexec/test-mldsa.py
```

The check exercises ML-DSA-44 and RSA root/intermediate/leaf chains, real FreeIPA
certificate import and HTTP key export, encrypted private key permissions, and
rejection of wrong hostnames, mismatched keys and untrusted chains.

For a full installation check on a Docker host with the `sysbox-runc` runtime:

```bash
sudo tests/full-install-mldsa.sh localhost/freeipa-server:mldsa44
```

The harness creates and removes its own container, internal network and volume.
Its temporary credentials and certificates stay inside that disposable volume.

Pushing this branch runs the dedicated workflow. It publishes
`ghcr.io/enucatl/freeipa-server:sha-<full-commit-sha>` and `:mldsa44` only after
the compatibility check passes. Pin a published digest for deployment. The
upstream matrix workflow excludes pushes to this branch.

A disposable CA-less server installation passed with the patched stock image:
administrator Kerberos authentication, `ipa ping`, TLS-verified HTTPS, and
LDAPS succeeded. Both HTTPS and LDAPS presented ML-DSA-44 certificates, and
no Dogtag CA instance was configured or running. This checks a new server;
existing account migration and production activation have not been performed.
