FROM ubuntu:24.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        git \
        openssh-client \
        sqlite3 \
        jq \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Generic in-container identity. The container is sandboxed and ephemeral;
# any commit it produces stays inside the container layer.
RUN git config --global user.name "nexum-tour" && \
    git config --global user.email "tour@example.invalid" && \
    git config --global init.defaultBranch main && \
    git config --global gpg.format ssh

WORKDIR /work
COPY tour.sh /work/tour.sh
COPY fixtures /work/fixtures
RUN chmod +x /work/tour.sh

ENTRYPOINT ["/work/tour.sh"]
