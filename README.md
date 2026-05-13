# cert-manager
> issues public and private SSL certificates using [Let's Encrypt](https://letsencrypt.org/) and [ca-private](https://github.com/balena-io/ca-private)

This service relies on [balena-ca](https://github.com/balena-io/balena-on-balena/tree/master/sidecars/balena-ca)
and generates the following structure, placing .ready file in the root of the volume to
signal that the volume contains complete set of PKI assets:

	/certs
	├── {{tld}}-chain.pem -> /certs/private/{{tld}}-chain.pem
	├── {{tld}}.key -> /certs/private/{{tld}}.key
	├── {{tld}}.pem -> /certs/private/{{tld}}.pem
	├── ca-bundle.pem -> /certs/private/ca-bundle.{{tld}}.pem
	├── private
	│   ├── {{tld}}-chain.pem
	│   ├── {{tld}}.key
	│   ├── {{tld}}.pem
	│   ├── api.{{tld}}.der
	│   ├── api.{{tld}}.key
	│   ├── api.{{tld}}.kid
	│   ├── api.{{tld}}.pem
	│   ├── ca-bundle.{{tld}}.pem
	│   ├── devices.{{tld}}.authorized_keys
	│   ├── devices.{{tld}}.ecdsa.key
	│   ├── devices.{{tld}}.ecdsa.key.pub
	│   ├── devices.{{tld}}.ed25519.key
	│   ├── devices.{{tld}}.ed25519.key.pub
	│   ├── devices.{{tld}}.rsa.key
	│   ├── devices.{{tld}}.rsa.key.pub
	│   ├── dhparam.{{tld}}.pem
	│   ├── git.{{tld}}.authorized_keys
	│   ├── git.{{tld}}.ecdsa.key
	│   ├── git.{{tld}}.ecdsa.key.pub
	│   ├── git.{{tld}}.ed25519.key
	│   ├── git.{{tld}}.ed25519.key.pub
	│   ├── git.{{tld}}.rsa.key
	│   ├── git.{{tld}}.rsa.key.pub
	│   ├── proxy.{{tld}}.authorized_keys
	│   ├── proxy.{{tld}}.ecdsa.key
	│   ├── proxy.{{tld}}.ecdsa.key.pub
	│   ├── proxy.{{tld}}.ed25519.key
	│   ├── proxy.{{tld}}.ed25519.key.pub
	│   ├── proxy.{{tld}}.rsa.key
	│   ├── proxy.{{tld}}.rsa.key.pub
	│   ├── root-ca.{{tld}}.pem
	│   ├── server-ca.{{tld}}.pem
	│   ├── vpn.{{tld}}.key
	│   └── vpn.{{tld}}.pem
	├── public
	│   └── (optional)
	├── export
	│   └── chain.pem
	├── root-ca.pem -> /certs/private/root-ca.{{tld}}.pem
	└── server-ca.pem -> /certs/private/server-ca.{{tld}}.pem

The public directory will contain the corresponding LetsEncrypt certificates, if:

* `DNS_TLD` does not end with .local (mDNS); and
* `DNS_TLD` points to a domain managed by CloudFlare or Gandi; and
* `CLOUDFLARE_API_TOKEN` or `GANDI_API_TOKEN` environment variable is present

In this instance, ${tld}-chain.pem will symlink to public/ instead.
