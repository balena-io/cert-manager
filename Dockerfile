FROM certbot/dns-cloudflare:v5.9.0@sha256:8216d4732d11772a9cf2fb30d022abf9eec7c83af2e33f002aa9e371c5192b67

# hadolint ignore=DL3018
RUN apk add --no-cache \
	aws-cli \
	bash \
	curl \
	gettext \
	jq \
	openssh \
	lockfile-progs \
	minio-client \
	&& apk add --no-cache --upgrade \
		ca-certificates \
		ca-certificates-bundle

WORKDIR /etc/letsencrypt

COPY entry.sh /usr/local/bin/

COPY _jwks.sh _keyid.sh *.json /opt/

ENTRYPOINT ["/bin/bash"]

CMD [ "-c", "/usr/local/bin/entry.sh" ]
