#!/usr/bin/env bash

# Generate a JWKS from <base>.pem, <base>.key and <base>.kid. Only public key
# material is emitted.

set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "Usage: ${0} <base>" >&2
	exit 1
fi

base="${1}"
pem="${base}.pem"
key="${base}.key"
kidfile="${base}.kid"

for f in "${pem}" "${key}" "${kidfile}"; do
	if [[ ! -r ${f} ]]; then
		echo "Error: cannot read ${f}" >&2
		exit 1
	fi
done

# base64url: no padding, no line wrapping.
function b64url {
	openssl base64 -A | tr '+/' '-_' | tr -d '='
}

kid="$(tr -d '[:space:]' <"${kidfile}")"

if [[ -z ${kid} ]]; then
	echo "Error: ${kidfile} is empty" >&2
	exit 1
fi

tmpspki="$(mktemp)"
trap 'rm -f "${tmpspki}"' EXIT

# Normalise to named-curve parameters and an uncompressed point. Compressed or
# explicit-parameter encodings change the SPKI layout, so the fixed offsets
# below would slice DER header bytes into the coordinates.
if ! openssl ec \
	-in "${key}" \
	-param_enc named_curve \
	-conv_form uncompressed \
	-pubout \
	-outform DER \
	-out "${tmpspki}" 2>/dev/null; then
	echo "Error: cannot read a public key from ${key}" >&2
	exit 1
fi

# alg is hardcoded to ES256 and the coordinates are fixed 32-byte slices, so
# reject anything but P-256. Its SPKI is always 91 bytes here; P-384 is 120 and
# RSA-2048 is 294. Captured rather than piped into 'grep -q', whose early exit
# can fail the pipeline under 'set -o pipefail'.
pubtext="$(openssl ec -in "${key}" -param_enc named_curve -pubout -text -noout 2>/dev/null)"

if [[ $(wc -c <"${tmpspki}") -ne 91 || ${pubtext} != *'prime256v1'* ]]; then
	echo "Error: ${key} is not an EC P-256 private key" >&2
	exit 1
fi

# The last 65 bytes are the point: 0x04 || X (32) || Y (32). 0x04 is 'BA=='.
if [[ "$(head -c 27 "${tmpspki}" | tail -c 1 | openssl base64 -A)" != 'BA==' ]]; then
	echo "Error: ${key} does not yield an uncompressed public point" >&2
	exit 1
fi

# Read from the file, not a pipe, so nothing can be truncated early.
x="$(head -c 59 "${tmpspki}" | tail -c 32 | b64url)"
y="$(tail -c 32 "${tmpspki}" | b64url)"

# x5t is the SHA-1 thumbprint of the DER-encoded certificate.
x5t="$(openssl x509 -in "${pem}" -outform DER | openssl dgst -sha1 -binary | b64url)"

jq -n \
	--arg x "${x}" \
	--arg y "${y}" \
	--arg kid "${kid}" \
	--arg x5t "${x5t}" \
	'{
		keys: [{
			kty: "EC",
			crv: "P-256",
			x: $x,
			y: $y,
			use: "sig",
			alg: "ES256",
			kid: $kid,
			x5t: $x5t
		}]
	}'
