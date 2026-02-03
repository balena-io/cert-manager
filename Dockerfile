FROM certbot/dns-cloudflare:v5.3.0

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
