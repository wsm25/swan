#!/usr/bin/env bash
# One-shot test PKI: local CA + server cert valid for both identities the
# swan4 client checks:
#   - rightid:    @stu.vpn.sjtu.edu.cn     (IKE responder certificate identity)
#   - aaa server: radius.net.sjtu.edu.cn   (PEAP TLS ServerName)
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p certs

if [ ! -f certs/caCert.pem ]; then
    echo ">>> generating test CA"
    openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
        -keyout certs/caKey.pem -out certs/caCert.pem \
        -subj "/CN=swan4-test-ca"
fi

if [ ! -f certs/serverCert.pem ]; then
    echo ">>> generating server certificate"
    openssl req -newkey rsa:2048 -sha256 -nodes \
        -keyout certs/serverKey.pem -out certs/server.csr \
        -subj "/CN=swan4-test-server"

    cat > certs/server-ext.cnf <<'EOF'
subjectAltName=DNS:stu.vpn.sjtu.edu.cn,DNS:radius.net.sjtu.edu.cn
extendedKeyUsage=serverAuth
EOF

    openssl x509 -req -in certs/server.csr \
        -CA certs/caCert.pem -CAkey certs/caKey.pem -CAcreateserial \
        -days 825 -sha256 -extfile certs/server-ext.cnf \
        -out certs/serverCert.pem
fi

chmod 600 certs/serverKey.pem
echo ">>> done: certs/caCert.pem, certs/serverCert.pem, certs/serverKey.pem"
echo ">>> client hint: SSL_CERT_FILE=$PWD/certs/caCert.pem"