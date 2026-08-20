FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap0.8 iproute2 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY generate_attacks.py ./

# Default writes a labelled corpus to the shared /captures volume.
ENTRYPOINT ["python", "generate_attacks.py"]
CMD ["--count", "400", "--benign", "400", \
     "--write", "/captures/mixed.pcap", \
     "--labels-out", "/captures/mixed.labels.json"]
