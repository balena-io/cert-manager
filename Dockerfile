FROM certbot/dns-cloudflare:amd64-v1.30.0 AS certbot-amd64

# hadolint ignore=DL3018
RUN apk add --no-cache \
	bash \
	curl \
	gettext \
	jq \
	nodejs \
	openssh

# https://dl.minio.io/client/mc/release/
ARG MINIOCLI_VERSION=20230412022151.0.0
ARG MINIOCLI_URL_x86_64=https://dl.minio.io/client/mc/release/linux-amd64/archive/mcli_${MINIOCLI_VERSION}_x86_64.apk
ARG MINIOCLI_URL_aarch64=https://dl.minio.io/client/mc/release/linux-arm64/archive/mcli_${MINIOCLI_VERSION}_aarch64.apk

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# hadolint ignore=DL3018
# https://docs.balena.io/learn/deploy/release-strategy/update-locking/#shell
RUN set -x ; apk add procmail --no-cache --repository http://dl-cdn.alpinelinux.org/alpine/v3.11/main/ \
	&& url="MINIOCLI_URL_$(apk --print-arch)" \
	&& curl -fsSL -O "${!url}" \
	&& [ "$(sha256sum "$(basename "${!url}")")" = "$(curl "${!url}.sha256sum")" ] \
	&& apk add --no-cache --allow-untrusted "$(basename "${!url}")" \
	&& rm "$(basename "${!url}")"

WORKDIR /etc/letsencrypt

COPY entry.sh /usr/local/bin/

COPY _keyid.js *.json /opt/

ENTRYPOINT ["/bin/bash"]

CMD [ "-c", "/usr/local/bin/entry.sh" ]
