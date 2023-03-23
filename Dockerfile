# https://hub.docker.com/r/certbot/certbot
# https://hub.docker.com/r/certbot/dns-cloudflare
FROM certbot/dns-cloudflare:amd64-v1.30.0 AS certbot-amd64
FROM certbot/dns-cloudflare:arm64v8-v1.30.0 AS certbot-arm64
FROM certbot-${TARGETARCH}

ARG MINIOCLI_VERSION=20221117212039.0.0

RUN apk add --no-cache \
	bash \
	curl \
	gettext \
	jq \
	nodejs \
	openssh

ARG TARGETARCH

RUN if [ "${TARGETARCH}" = "amd64" ]; then MINIO_APK_ARCH="x86_64"; else MINIO_APK_ARCH="aarch64"; fi \
	&& apk add procmail --no-cache --repository http://dl-cdn.alpinelinux.org/alpine/v3.11/main/ \
	&& wget https://dl.minio.io/client/mc/release/linux-${TARGETARCH}/archive/mcli_${MINIOCLI_VERSION}_${MINIO_APK_ARCH}.apk \
	&& [ "$(sha256sum mcli_${MINIOCLI_VERSION}_${MINIO_APK_ARCH}.apk)" = "$(curl https://dl.minio.io/client/mc/release/linux-${TARGETARCH}/archive/mcli_${MINIOCLI_VERSION}_${MINIO_APK_ARCH}.apk.sha256sum)" ] \
	&& apk add --allow-untrusted mcli_${MINIOCLI_VERSION}_${MINIO_APK_ARCH}.apk \
	&& rm mcli_${MINIOCLI_VERSION}_${MINIO_APK_ARCH}.apk

RUN wget -q https://raw.githubusercontent.com/balena-io/open-balena/master/scripts/_keyid.js -O /opt/_keyid.js

WORKDIR /etc/letsencrypt

COPY entry.sh /usr/local/bin/

COPY *.json /opt/

ENTRYPOINT ["/bin/bash"]

CMD [ "-c", "/usr/local/bin/entry.sh" ]
