#!/usr/bin/python3
"""Exercise FreeIPA's real certificate import and HTTP setup in a disposable image."""

from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

import cryptography
from cryptography.hazmat.primitives.serialization import load_pem_private_key

print("cryptography: " + cryptography.__version__)
assert not Path("/etc/ipa/ca.crt").exists(), "Refusing an installed IPA server"
# The upstream image keeps its trust store behind /data until its normal init runs.
if not Path("/etc/pki/tls/cert.pem").exists():
    shutil.copytree(
        "/data-template/etc/pki", "/data/etc/pki", symlinks=True, dirs_exist_ok=True
    )

from ipalib import x509
from ipaserver.install.installutils import load_pkcs12
from ipaserver.install import httpinstance, ipa_server_certinstall


def run(*args: str, data: bytes | None = None) -> bytes:
    """Run a probe command and return its captured output."""
    return subprocess.run(args, input=data, check=True, capture_output=True).stdout


for algorithm in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "RSA:2048", "EC"]:
    with tempfile.TemporaryDirectory(prefix="ipa-mldsa-") as directory:
        root = Path(directory)

        def req(name: str, subject: str, ca: bool = False) -> None:
            """Generate a disposable certificate request or root certificate."""
            args = [
                "openssl",
                "req",
                "-new",
                "-newkey",
                algorithm,
                "-noenc",
                "-keyout",
                str(root / (name + ".key")),
                "-out",
                str(root / (name + ".crt" if ca else name + ".csr")),
                "-subj",
                "/CN=" + subject,
            ]
            if algorithm.startswith("ML-DSA"):
                args += ["-provparam", "ml-dsa.output_formats=seed-only"]
            if algorithm == "EC":
                args += ["-pkeyopt", "ec_paramgen_curve:P-256"]
            if ca:
                args += [
                    "-x509",
                    "-days",
                    "1",
                    "-addext",
                    "basicConstraints=critical,CA:TRUE",
                ]
            run(*args)

        def sign(name: str, issuer: str, extensions: str) -> None:
            """Sign a disposable certificate with its test issuer."""
            ext = root / (name + ".cnf")
            ext.write_text(extensions)
            forced_key = (
                ["-force_pubkey", str(root / "compressed.pub")]
                if name == "server" and algorithm == "EC"
                else []
            )
            run(
                "openssl",
                "x509",
                "-req",
                "-in",
                str(root / (name + ".csr")),
                "-CA",
                str(root / (issuer + ".crt")),
                "-CAkey",
                str(root / (issuer + ".key")),
                "-CAcreateserial",
                "-days",
                "1",
                "-extfile",
                str(ext),
                "-out",
                str(root / (name + ".crt")),
                *forced_key,
            )

        req("ca", "probe-root", ca=True)
        req("intermediate", "probe-intermediate")
        sign(
            "intermediate",
            "ca",
            "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n",
        )
        req("server", "ipa.home.arpa")
        if algorithm == "EC":
            # A compressed certificate key must match an uncompressed private key.
            (root / "compressed.pub").write_bytes(
                run(
                    "openssl",
                    "pkey",
                    "-in",
                    str(root / "server.key"),
                    "-pubout",
                    "-ec_conv_form",
                    "compressed",
                )
            )
        sign(
            "server",
            "intermediate",
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature"
            + (",keyEncipherment" if algorithm.startswith("RSA") else "")
            + "\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:ipa.home.arpa\n",
        )
        chain = root / "chain.crt"
        chain.write_bytes(
            (root / "intermediate.crt").read_bytes() + (root / "ca.crt").read_bytes()
        )
        source_cert = root / "server.crt"
        source_key = root / "server.key"
        cert = x509.load_certificate_from_file(str(source_cert))
        expected_spki = run(
            "openssl", "pkey", "-in", str(source_key), "-pubout", "-outform", "DER"
        )

        assert cert.public_key_info_bytes == expected_spki
        source_private_key = load_pem_private_key(source_key.read_bytes(), None)

        p12, password, ca = load_pkcs12(
            [str(source_cert), str(source_key)],
            None,
            None,
            [str(chain)],
            host_name="ipa.home.arpa",
        )
        assert (
            ca.subject
            == x509.load_certificate_from_file(str(root / "intermediate.crt")).subject
        )
        fake = SimpleNamespace(
            pkcs12_info=(p12.name, password),
            ca_is_configured=False,
            add_cert_to_service=lambda: None,
        )
        targets = SimpleNamespace(
            OPENSSL="/usr/bin/openssl",
            HTTPD_PASSWD_FILE_FMT=str(root / "http-password"),
            HTTPD_CERT_FILE=str(root / "http.crt"),
            HTTPD_KEY_FILE=str(root / "http.key"),
        )
        with (
            patch.object(httpinstance, "paths", targets),
            patch.object(
                httpinstance,
                "api",
                SimpleNamespace(env=SimpleNamespace(host="ipa.home.arpa")),
            ),
        ):
            httpinstance.HTTPInstance._HTTPInstance__setup_ssl(fake)
        assert (root / "http.key").stat().st_mode & 0o777 == 0o600
        assert b"BEGIN ENCRYPTED PRIVATE KEY" in (root / "http.key").read_bytes()
        installed_key = load_pem_private_key(
            (root / "http.key").read_bytes(), (root / "http-password").read_bytes()
        )
        assert installed_key.public_key() == source_private_key.public_key()
        if algorithm.startswith("ML-DSA"):
            assert (
                installed_key.private_bytes_raw()
                == source_private_key.private_bytes_raw()
            )
        output_spki = run(
            "openssl",
            "pkey",
            "-in",
            str(root / "http.key"),
            "-passin",
            "file:" + str(root / "http-password"),
            "-pubout",
            "-outform",
            "DER",
        )
        assert output_spki == expected_spki
        assert (
            x509.load_certificate_from_file(
                str(root / "http.crt")
            ).public_key_info_bytes
            == cert.public_key_info_bytes
        )
        p12.close()

        renewal = SimpleNamespace(
            args=[str(source_cert), str(source_key)],
            options=SimpleNamespace(pin=None, cert_name=None),
        )
        renewed_cert, renewed_key, _ = (
            ipa_server_certinstall.ServerCertInstall.load_pkcs12(
                renewal, ca_chain_fname=str(chain), host_name="ipa.home.arpa"
            )
        )
        assert renewed_cert == cert
        assert renewed_key.public_key() == source_private_key.public_key()
        if algorithm.startswith("ML-DSA"):
            assert (
                renewed_key.private_bytes_raw()
                == source_private_key.private_bytes_raw()
            )

        req("untrusted", "untrusted-root", ca=True)
        for label, hostname, private_key, trust in [
            ("wrong hostname", "wrong.home.arpa", source_key, chain),
            ("mismatched key", "ipa.home.arpa", root / "ca.key", chain),
            ("wrong chain", "ipa.home.arpa", source_key, root / "untrusted.crt"),
        ]:
            try:
                result, _, _ = load_pkcs12(
                    [str(source_cert), str(private_key)],
                    None,
                    None,
                    [str(trust)],
                    host_name=hostname,
                )
            except Exception:
                pass
            else:
                result.close()
                raise AssertionError("Accepted " + label)
        print(
            algorithm
            + ": full-chain import, HTTP key export, certificate renewal, hostname/key/chain rejection passed"
        )
