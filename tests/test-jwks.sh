#!/usr/bin/env bash

# Known-answer test for /opt/_keyid.sh and /opt/_jwks.sh. Expected values come
# from the Node implementation these scripts replaced, so a base-image change
# that alters the key ID or JWKS fails here instead of breaking token auth.

set -eo pipefail

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

cat >"${workdir}/api.key" <<'EOF'
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIExEXDNy5EKkx7gWDtVgmXbCkf4M3Ydxzj8BHeyG+vuxoAoGCCqGSM49
AwEHoUQDQgAEoAgYRVMCp7YEhMxyzTowzfZN4kumPUOXm5o7Ax69MJ4MlR+Y++1g
9OSq83/VxwvJS8twwM2JyXO7pSvXbesDGg==
-----END EC PRIVATE KEY-----
EOF

cat >"${workdir}/api.pem" <<'EOF'
-----BEGIN CERTIFICATE-----
MIIBezCCASKgAwIBAgIBATAKBggqhkjOPQQDAjAcMRowGAYDVQQDDBFhcGkudGVz
dGluZy5sb2NhbDAgFw0yMDAxMDEwMDAwMDBaGA8yMDk5MTIzMTIzNTk1OVowHDEa
MBgGA1UEAwwRYXBpLnRlc3RpbmcubG9jYWwwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAASgCBhFUwKntgSEzHLNOjDN9k3iS6Y9Q5ebmjsDHr0wngyVH5j77WD05Krz
f9XHC8lLy3DAzYnJc7ulK9dt6wMao1MwUTAdBgNVHQ4EFgQU7VpEjbNbf6V5Xq/9
x9wP7LEMOZIwHwYDVR0jBBgwFoAU7VpEjbNbf6V5Xq/9x9wP7LEMOZIwDwYDVR0T
AQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiA2lxe+ftRd8WIYzZnWfYykuXXr
ma46su6PIEF29u7oqgIgPyNnjr43akUBA3POVHH8nsujsjEom8AFPpUx3bpOlMI=
-----END CERTIFICATE-----
EOF

expected_kid='WTJJ:7VBC:34AL:6NG2:C26V:BF5U:ELFU:64W7:B4GN:5F55:JPEA:CT2U'
expected_x='oAgYRVMCp7YEhMxyzTowzfZN4kumPUOXm5o7Ax69MJ4'
expected_y='DJUfmPvtYPTkqvN_1ccLyUvLcMDNiclzu6Ur123rAxo'
expected_x5t='QzKsf9ua_KpuxJzPB-LsBvyM7gA'

function check {
	local name expected actual
	name="${1}"
	expected="${2}"
	actual="${3}"

	if [[ ${actual} != "${expected}" ]]; then
		echo "FAIL: ${name}: expected '${expected}', got '${actual}'" >&2
		exit 1
	fi

	echo "ok: ${name}"
}

function check_fails {
	local name status output
	name="${1}"
	shift

	# The caller redirects stdout straight into the target file, so a failing
	# script must exit non-zero and write nothing.
	status=0
	output="$("${@}" 2>/dev/null)" || status="${?}"

	if [[ ${status} -eq 0 ]]; then
		echo "FAIL: ${name}: expected a non-zero exit status" >&2
		exit 1
	fi

	if [[ -n ${output} ]]; then
		echo "FAIL: ${name}: wrote to stdout before failing" >&2
		exit 1
	fi

	echo "ok: ${name} (exit ${status}, no output)"
}

# Mirrors compute_api_kid() in entry.sh.
openssl ec \
	-in "${workdir}/api.key" \
	-pubout \
	-outform DER \
	-out "${workdir}/api.der"

/opt/_keyid.sh "${workdir}/api.der" >"${workdir}/api.kid"

check kid "${expected_kid}" "$(cat "${workdir}/api.kid")"

/opt/_jwks.sh "${workdir}/api" >"${workdir}/api.jwks.json"

check kty EC "$(jq -r '.keys[0].kty' <"${workdir}/api.jwks.json")"
check crv P-256 "$(jq -r '.keys[0].crv' <"${workdir}/api.jwks.json")"
check use sig "$(jq -r '.keys[0].use' <"${workdir}/api.jwks.json")"
check alg ES256 "$(jq -r '.keys[0].alg' <"${workdir}/api.jwks.json")"
check x "${expected_x}" "$(jq -r '.keys[0].x' <"${workdir}/api.jwks.json")"
check y "${expected_y}" "$(jq -r '.keys[0].y' <"${workdir}/api.jwks.json")"
check x5t "${expected_x5t}" "$(jq -r '.keys[0].x5t' <"${workdir}/api.jwks.json")"
check "jwks kid" "${expected_kid}" "$(jq -r '.keys[0].kid' <"${workdir}/api.jwks.json")"

# The private scalar must never reach the JWKS.
if jq -e '.keys[0].d' <"${workdir}/api.jwks.json" >/dev/null 2>&1; then
	echo "FAIL: private 'd' component present in JWKS" >&2
	exit 1
fi

echo "ok: no private key material in JWKS"

# These encodings change the SPKI layout. A generator that slices fixed byte
# offsets without normalising emits a valid-looking JWKS holding the wrong key.
for encoding in 'compressed' 'explicit'; do
	variant="${workdir}/${encoding}"
	mkdir -p "${variant}"
	cp "${workdir}/api.pem" "${workdir}/api.kid" "${variant}/"

	case "${encoding}" in
	compressed)
		openssl ec -in "${workdir}/api.key" \
			-conv_form compressed \
			-out "${variant}/api.key" 2>/dev/null
		;;
	explicit)
		openssl ec -in "${workdir}/api.key" \
			-param_enc explicit \
			-out "${variant}/api.key" 2>/dev/null
		;;
	esac

	/opt/_jwks.sh "${variant}/api" >"${variant}/api.jwks.json"

	check "${encoding} x" "${expected_x}" "$(jq -r '.keys[0].x' <"${variant}/api.jwks.json")"
	check "${encoding} y" "${expected_y}" "$(jq -r '.keys[0].y' <"${variant}/api.jwks.json")"
done

# A hand-edited kid file may carry whitespace; it must not reach the JWKS.
mkdir -p "${workdir}/trim"
cp "${workdir}/api.key" "${workdir}/api.pem" "${workdir}/trim/"
printf '\n  %s \t\n' "${expected_kid}" >"${workdir}/trim/api.kid"

check 'kid whitespace stripped' \
	"${expected_kid}" \
	"$(/opt/_jwks.sh "${workdir}/trim/api" | jq -r '.keys[0].kid')"

# Error paths. Each must exit non-zero rather than emit a partial JWKS.
check_fails 'no arguments' /opt/_jwks.sh
check_fails 'too many arguments' /opt/_jwks.sh "${workdir}/api" "${workdir}/api"
check_fails 'missing base' /opt/_jwks.sh "${workdir}/does-not-exist"

mkdir -p "${workdir}/nopem"
cp "${workdir}/api.key" "${workdir}/api.kid" "${workdir}/nopem/"
check_fails 'missing certificate' /opt/_jwks.sh "${workdir}/nopem/api"

mkdir -p "${workdir}/nokid"
cp "${workdir}/api.key" "${workdir}/api.pem" "${workdir}/nokid/"
check_fails 'missing kid file' /opt/_jwks.sh "${workdir}/nokid/api"

mkdir -p "${workdir}/emptykid"
cp "${workdir}/api.key" "${workdir}/api.pem" "${workdir}/emptykid/"
printf '\n \n' >"${workdir}/emptykid/api.kid"
check_fails 'blank kid file' /opt/_jwks.sh "${workdir}/emptykid/api"

# alg is hardcoded to ES256, so a non-P-256 key must be refused.
mkdir -p "${workdir}/rsa"
cp "${workdir}/api.pem" "${workdir}/api.kid" "${workdir}/rsa/"
openssl genrsa -out "${workdir}/rsa/api.key" 2048 2>/dev/null
check_fails 'rsa key rejected' /opt/_jwks.sh "${workdir}/rsa/api"

mkdir -p "${workdir}/badkey"
cp "${workdir}/api.pem" "${workdir}/api.kid" "${workdir}/badkey/"
echo 'not a key' >"${workdir}/badkey/api.key"
check_fails 'unparseable key rejected' /opt/_jwks.sh "${workdir}/badkey/api"

mkdir -p "${workdir}/badpem"
cp "${workdir}/api.key" "${workdir}/api.kid" "${workdir}/badpem/"
echo 'not a certificate' >"${workdir}/badpem/api.pem"
check_fails 'unparseable certificate rejected' /opt/_jwks.sh "${workdir}/badpem/api"

mkdir -p "${workdir}/p384"
cp "${workdir}/api.pem" "${workdir}/api.kid" "${workdir}/p384/"
openssl ecparam -name secp384r1 -genkey -noout -out "${workdir}/p384/api.key" 2>/dev/null
check_fails 'p-384 key rejected' /opt/_jwks.sh "${workdir}/p384/api"

echo "JWKS generation verified."
