FROM certbot/dns-cloudflare:v5.7.0@sha256:3bd60102cdef55294a44ffbff10bb54dd086803aa57d3f854933b756d305fbb8

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
