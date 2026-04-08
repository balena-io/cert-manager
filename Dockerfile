FROM certbot/dns-cloudflare:v5.6.0@sha256:4231f04709b3ed4f457c939bdf2942bd9be603e28fe0eeb9c2c223a313302869

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
