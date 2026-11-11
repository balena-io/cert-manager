FROM certbot/dns-cloudflare:v5.10.0@sha256:6d5e1e84f687ce81786c97cbeccb9dda94d86bbb29a81dbb85527bd68008d77d

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
