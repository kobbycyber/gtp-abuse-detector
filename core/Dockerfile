FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Open5GS from the maintained PPA + mongosh (open5gs-dbctl and the
# entrypoint's health-wait both shell out to it; it ships from MongoDB's own
# repo, not Ubuntu's, and not as a dependency of the open5gs package).
RUN apt-get update && apt-get install -y --no-install-recommends \
        software-properties-common gnupg curl ca-certificates \
        iproute2 iptables iputils-ping tcpdump jq && \
    add-apt-repository -y ppa:open5gs/latest && \
    curl -fsSL https://pgp.mongodb.com/server-7.0.asc | \
        gpg --dearmor -o /usr/share/keyrings/mongodb-server-7.0.gpg && \
    echo "deb [ arch=amd64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" \
        > /etc/apt/sources.list.d/mongodb-org-7.0.list && \
    apt-get update && apt-get install -y --no-install-recommends \
        open5gs mongodb-mongosh && \
    curl -fsSL https://raw.githubusercontent.com/open5gs/open5gs/main/misc/db/open5gs-dbctl \
        -o /usr/local/bin/open5gs-dbctl && chmod +x /usr/local/bin/open5gs-dbctl && \
    rm -rf /var/lib/apt/lists/*

# Config overrides (bind addresses, PLMN, TAC) and startup logic.
COPY configs/ /etc/open5gs/override/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# N2/NGAP (SCTP 38412), N3/GTP-U (UDP 2152)
EXPOSE 38412/sctp 2152/udp

ENTRYPOINT ["/entrypoint.sh"]
