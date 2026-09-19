FROM ubuntu:22.04

# Install minimal tools: bash, coreutils, curl (for web testing)
RUN apt-get update && apt-get install -y --no-install-recommends bash coreutils curl \
    && apt-get purge -y wget netcat-openbsd openssh-server \
    && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# Add labuser
RUN useradd -m -s /bin/bash labuser

USER labuser
