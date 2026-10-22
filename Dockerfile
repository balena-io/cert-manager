FROM node:26.12.1-alpine3.23@sha256:bc2b334006f15c7167bbeb2f08f28c2df883f7594a0470e04454ebe7560cfe68 AS node

FROM certbot/dns-cloudflare:v5.8.0@sha256:c45edb002b883da1a1235abb205dff474a7a1a459d878e8d5fdc7f9d83073aea

# hadolint ignore=DL3018
RUN apk add --no-cache \
	aws-cli \
	bash \
	curl \
	gettext \
	jq \
	libatomic \
	libstdc++ \
	openssh \
	lockfile-progs \
	minio-client \
	&& apk add --no-cache --upgrade \
		ca-certificates=20261020-r0 \
		ca-certificates-bundle=20261020-r0

COPY --from=node /usr/local/bin/node /usr/local/bin/node

WORKDIR /etc/letsencrypt

COPY entry.sh /usr/local/bin/

COPY _jwks.js _keyid.js *.json /opt/

ENTRYPOINT ["/bin/bash"]

CMD [ "-c", "/usr/local/bin/entry.sh" ]
