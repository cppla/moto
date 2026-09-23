FROM python:3.13-slim-bookworm

RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates iproute2 iptables \
    && rm -rf /var/lib/apt/lists/*

# The test binary, private configuration and origin CA are mounted read-only.
# Never use host networking: fault injection belongs to this container only.
WORKDIR /test
