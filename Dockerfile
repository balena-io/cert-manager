FROM certbot/dns-cloudflare:v5.8.0@sha256:c45edb002b883da1a1235abb205dff474a7a1a459d878e8d5fdc7f9d83073aea

# hadolint ignore=DL3018
RUN apk add --no-cache \
	bash \
	curl \
	gettext \
	jq \
	nodejs \
	openssh \
	lockfile-progs \
	minio-client

WORKDIR /etc/letsencrypt

COPY entry.sh /usr/local/bin/

COPY _jwks.js _keyid.js *.json /opt/

ENTRYPOINT ["/bin/bash"]

CMD [ "-c", "/usr/local/bin/entry.sh" ]
