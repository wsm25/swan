# swan4 e2e responder: Debian strongSwan (GCM-capable) + FreeRADIUS AAA
# backend in one container. FreeRADIUS answers EAP-PEAP/MSCHAPv2 on
# 127.0.0.1:1812; charon forwards inner EAP via eap-radius.
#
# Build context: tests/docker
#   podman build -t swan4-e2e .
# Run:
#   podman run --rm --name swan4-ss --cap-add NET_ADMIN --cap-add NET_RAW \
#     -p 4500:4500/udp swan4-e2e
FROM debian:12

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    strongswan \
    libcharon-extra-plugins \
    libcharon-extauth-plugins \
    libstrongswan-standard-plugins \
    freeradius \
    freeradius-utils \
    ca-certificates \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# ---- strongSwan side ----
COPY certs/caCert.pem     /etc/ipsec.d/cacerts/caCert.pem
COPY certs/serverCert.pem /etc/ipsec.d/certs/serverCert.pem
COPY certs/serverKey.pem  /etc/ipsec.d/private/serverKey.pem
RUN chmod 600 /etc/ipsec.d/private/serverKey.pem

COPY ipsec.conf      /etc/ipsec.conf
COPY ipsec.secrets   /etc/ipsec.secrets
RUN chmod 600 /etc/ipsec.secrets
COPY strongswan.conf /etc/strongswan.conf

# ---- FreeRADIUS side ----
COPY certs/caCert.pem     /etc/freeradius/3.0/certs/caCert.pem
COPY certs/serverCert.pem /etc/freeradius/3.0/certs/serverCert.pem
COPY certs/serverKey.pem  /etc/freeradius/3.0/certs/serverKey.pem
RUN chown -R freerad:freerad /etc/freeradius/3.0/certs \
    && chmod 600 /etc/freeradius/3.0/certs/serverKey.pem

COPY freeradius/raddb/clients.conf /etc/freeradius/3.0/clients.conf
COPY freeradius/raddb/users        /etc/freeradius/3.0/users
COPY freeradius/raddb/eap          /etc/freeradius/3.0/mods-enabled/eap
COPY freeradius/raddb/mschap       /etc/freeradius/3.0/mods-enabled/mschap
COPY freeradius/raddb/authorize    /etc/freeradius/3.0/mods-config/files/authorize

COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 500/udp 4500/udp 1812/udp

CMD ["/entrypoint.sh"]