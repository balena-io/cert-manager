# https://hub.docker.com/r/certbot/certbot
# https://hub.docker.com/r/certbot/dns-cloudflare
ARG ARCH=amd64
FROM certbot/dns-cloudflare:${ARCH}-v1.30.0

ARG MINIOCLI_VERSION=20220916091647.0.0

RUN apk add --no-cache \
    bash \
    curl \
    gettext \
    jq \
    nodejs \
    openssh

RUN apk add procmail --no-cache --repository http://dl-cdn.alpinelinux.org/alpine/v3.3/main/ \
    && wget https://dl.minio.io/client/mc/release/linux-amd64/mcli_${MINIOCLI_VERSION}_x86_64.apk \
    && [ "$(sha256sum mcli_${MINIOCLI_VERSION}_x86_64.apk)" = "$(curl https://dl.minio.io/client/mc/release/linux-amd64/mcli_${MINIOCLI_VERSION}_x86_64.apk.sha256sum)" ] \
    && apk add --allow-untrusted mcli_${MINIOCLI_VERSION}_x86_64.apk \
    && rm mcli_${MINIOCLI_VERSION}_x86_64.apk

RUN wget -q https://raw.githubusercontent.com/balena-io/open-balena/master/scripts/_keyid.js -O /opt/_keyid.js

WORKDIR /etc/letsencrypt

COPY entry.sh /usr/local/bin/

COPY *.json /opt/

ENTRYPOINT ["/bin/bash"]

CMD [ "-c", "/usr/local/bin/entry.sh" ]
