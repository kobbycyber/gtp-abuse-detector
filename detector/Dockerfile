FROM python:3.12-slim

# libpcap for live sniffing; tcpdump handy for debugging inside the container
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap0.8 tcpdump iproute2 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY rules.py metrics.py gtpu_detector.py ./
COPY tests ./tests

# Default: sit on the shared core netns and watch N3 (udp/2152).
ENTRYPOINT ["python", "gtpu_detector.py"]
CMD ["live", "--iface", "eth0", "--core-ips", "10.10.10.10", "--json"]
