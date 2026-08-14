FROM ubuntu:22.04

# Remove unnecessary tools
RUN apt-get update && apt-get install -y --no-install-recommends bash coreutils \
    && apt-get purge -y curl wget netcat-openbsd openssh-server \
    && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# Add labuser
RUN useradd -m -s /bin/bash labuser

USER labuser
