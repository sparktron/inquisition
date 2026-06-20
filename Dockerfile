# Inquisition container image.
#
# Build:  docker build -t inquisition .
# Run:    docker run --rm inquisition example.com --yes --depth quick
#
# openssl is installed for the weak-Diffie-Hellman TLS probe; everything else is
# pure Python. Runs as a non-root user with /data as a writable working dir
# (reports and the audit log land there).
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY . /src
RUN pip install --no-cache-dir /src \
    && useradd -m -u 10001 inquisitor \
    && mkdir -p /data \
    && chown inquisitor /data

USER inquisitor
WORKDIR /data

# Default metrics scrape port (see examples/docker-compose.yml).
EXPOSE 9090

ENTRYPOINT ["inquisition"]
CMD ["--help"]
