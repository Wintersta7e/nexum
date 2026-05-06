FROM ubuntu:24.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        git \
        openssh-client \
        sqlite3 \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Generic in-container identity. The container is sandboxed and ephemeral;
# any commit it produces stays inside the container layer.
RUN git config --global user.name "nexum-e2e" && \
    git config --global user.email "e2e@example.invalid" && \
    git config --global init.defaultBranch main && \
    git config --global gpg.format ssh

WORKDIR /work
COPY run-test.sh /work/run-test.sh
COPY fixtures /work/fixtures
RUN chmod +x /work/run-test.sh

ENTRYPOINT ["/work/run-test.sh"]
