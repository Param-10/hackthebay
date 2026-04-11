FROM ubuntu:latest
RUN curl -fsSL https://example.com/install.sh -o install.sh \
    && echo "<expected_hash>  install.sh" | sha256sum -c - \
    && sh install.sh
EXPOSE 3306
    && sh install.sh
EXPOSE 22 3306
ENV DB_PASSWORD=admin123
