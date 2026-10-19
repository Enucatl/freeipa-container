#!/bin/bash
# Destructive only to fresh named Docker resources; never mounts host IPA state.
set -euo pipefail
image=${1:?Usage: tests/full-install-mldsa.sh IMAGE}
name=ipa-mldsa-probe-$(cat /proc/sys/kernel/random/uuid)
volume=$name-data
network=$name-net
cleanup() {
    if [ "$?" -ne 0 ]; then
        docker logs "$name" >&2 || true
        docker exec "$name" tail -n 100 /var/log/ipaserver-install.log >&2 || true
    fi
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker volume rm "$volume" >/dev/null 2>&1 || true
    docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker volume create "$volume" >/dev/null
docker network create --internal "$network" >/dev/null
docker run --rm -i --network none -v "$volume":/data --entrypoint bash "$image" <<'GEN'
set -eu
umask 077
mkdir /data/probe
cd /data/probe
openssl req -x509 -newkey ML-DSA-44 -keyout ca.key -out ca.crt -noenc -subj /CN=probe-ca -days 1 -addext basicConstraints=critical,CA:TRUE 2>/dev/null
openssl req -new -newkey ML-DSA-44 -keyout intermediate.key -out intermediate.csr -noenc -subj /CN=probe-intermediate 2>/dev/null
printf '%s\n' 'basicConstraints=critical,CA:TRUE,pathlen:0' 'keyUsage=critical,keyCertSign,cRLSign' 'subjectKeyIdentifier=hash' >ca-ext.cnf
openssl x509 -req -in intermediate.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out intermediate.crt -days 1 -extfile ca-ext.cnf 2>/dev/null
cat intermediate.crt ca.crt >chain.crt
openssl req -new -newkey ML-DSA-44 -keyout server.key -out server.csr -noenc -subj /CN=ipa.home.arpa 2>/dev/null
printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' 'extendedKeyUsage=serverAuth,clientAuth' 'subjectAltName=DNS:ipa.home.arpa' >ext.cnf
openssl x509 -req -in server.csr -CA intermediate.crt -CAkey intermediate.key -CAcreateserial -out server.crt -days 1 -extfile ext.cnf 2>/dev/null
python3 - <<'PY'
import secrets
from pathlib import Path
password=secrets.token_urlsafe(32)
Path('password').write_text(password)
Path('/data/ipa-server-install-options').write_text('--admin-password='+password+'\n--ds-password='+password+'\n')
PY
GEN
docker run -d --name "$name" --tmpfs /run --tmpfs /tmp --sysctl net.ipv6.conf.all.disable_ipv6=0 --hostname ipa.home.arpa --network "$network" -v "$volume":/data "$image" no-exit --unattended --realm HOME.ARPA --domain home.arpa --hostname ipa.home.arpa --no-pkinit --no-ntp --no-host-dns --dirsrv-cert-file /data/probe/server.crt --dirsrv-cert-file /data/probe/server.key --http-cert-file /data/probe/server.crt --http-cert-file /data/probe/server.key --ca-cert-file /data/probe/chain.crt --dirsrv-pin= --http-pin= >/dev/null
# Wait for systemd, then block until installation finishes.
timeout 600 docker exec "$name" bash -c 'while ! test -S /run/dbus/system_bus_socket; do sleep 1; done; systemctl start ipa-server-configure-first.service'

docker exec -i "$name" bash -s <<'VERIFY'
set -euo pipefail
kinit admin < /data/probe/password >/dev/null
ipa ping
curl --silent --show-error --fail --cacert /data/probe/ca.crt https://ipa.home.arpa/ipa/ui/ >/dev/null
LDAPTLS_CACERT=/data/probe/ca.crt ldapsearch -LLL -x -H ldaps://ipa.home.arpa -b "" -s base namingContexts | grep -F 'namingContexts: dc=home,dc=arpa'
test ! -d /etc/pki/pki-tomcat
test ! -d /var/lib/pki/pki-tomcat/ca
for port in 443 636; do
    openssl s_client -connect ipa.home.arpa:$port -servername ipa.home.arpa -CAfile /data/probe/ca.crt -verify_return_error </dev/null > /tmp/verified-tls 2>&1
    grep -F 'Peer signature type: mldsa44' /tmp/verified-tls
    grep -F 'Verify return code: 0 (ok)' /tmp/verified-tls
done
VERIFY
echo 'Fresh CA-less FreeIPA installation, admin Kerberos/API, HTTPS and LDAPS passed'
