# https://hub.docker.com/r/certbot/certbot
# https://hub.docker.com/r/certbot/dns-cloudflare
ARG ARCH=amd64
FROM certbot/dns-cloudflare:${ARCH}-v1.20.0

RUN apk add --no-cache \
    bash \
    curl \
    jq \
    nodejs \
    openssh

RUN wget -q https://raw.githubusercontent.com/balena-io/open-balena/master/scripts/_keyid.js -O /opt/_keyid.js

WORKDIR /etc/letsencrypt

COPY entry.sh /usr/local/bin/

ENTRYPOINT ["/bin/bash"]

CMD [ "-c", "/usr/local/bin/entry.sh" ]
