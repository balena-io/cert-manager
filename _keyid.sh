#!/usr/bin/env bash

# Derive a JOSE key ID from a DER-encoded public key: base32 of the first 30
# bytes of the SHA-256 digest, in 4-character groups. Matches
# https://github.com/balena-io/open-balena/blob/master/scripts/gen-token-auth-cert

set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "Usage: ${0} <der-file>" >&2
	exit 1
fi

der="${1}"

if [[ ! -r ${der} ]]; then
	echo "Error: cannot read ${der}" >&2
	exit 1
fi

# 30 bytes (60 hex characters) is 240 bits, a multiple of 5, so base32 needs no
# padding.
digest="$(openssl dgst -sha256 "${der}")"
digest="${digest##* }"
digest="${digest:0:60}"

if [[ ! ${digest} =~ ^[0-9a-f]{60}$ ]]; then
	echo "Error: unexpected digest output for ${der}" >&2
	exit 1
fi

alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
b32=''

# 5 bytes (10 hex characters) become 8 base32 characters.
for ((i = 0; i < 60; i += 10)); do
	group=$((16#${digest:i:10}))
	for ((bit = 35; bit >= 0; bit -= 5)); do
		b32+="${alphabet:$(((group >> bit) & 31)):1}"
	done
done

kid=''
for ((i = 0; i < ${#b32}; i += 4)); do
	kid+="${b32:i:4}:"
done

printf '%s' "${kid%:}"
