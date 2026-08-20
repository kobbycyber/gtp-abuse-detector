FROM ubuntu:22.04 AS build
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        git make gcc g++ cmake libsctp-dev lksctp-tools ca-certificates && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
ARG UERANSIM_REF=v3.2.6
RUN git clone --depth 1 --branch ${UERANSIM_REF} https://github.com/aligungr/UERANSIM . && \
    make -j"$(nproc)"

FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        libsctp-dev lksctp-tools iproute2 iputils-ping tcpdump && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /ueransim
COPY --from=build /src/build/ ./build/
COPY gnb.yaml ue.yaml ./config/
COPY run.sh /run.sh
RUN chmod +x /run.sh ./build/nr-binder
ENTRYPOINT ["/run.sh"]
