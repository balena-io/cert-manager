FROM certbot/dns-cloudflare:v5.7.0@sha256:2d4509d3643716775242d77acf61082c384f9b74aa9696146e2a35a39ffa2e02

# hadolint ignore=DL3018
RUN apk add --no-cache \
	aws-cli \
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
