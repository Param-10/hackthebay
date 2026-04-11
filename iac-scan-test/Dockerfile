FROM ubuntu:latest
RUN curl -fsSL https://example.com/install.sh -o install.sh \
    && echo "<expected_hash>  install.sh" | sha256sum -c - \
    && sh install.sh
# rescan with new key
