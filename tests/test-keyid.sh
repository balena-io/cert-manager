#!/usr/bin/env bash

# Known-answer tests for /opt/_keyid.sh. Expected values come from an
# independent implementation (Python base64.b32encode), not from the script
# under test, so a base-image change to openssl or bash arithmetic fails here.

set -eo pipefail

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

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
	local name status
	name="${1}"
	shift

	status=0
	"${@}" >/dev/null 2>&1 || status="${?}"

	if [[ ${status} -eq 0 ]]; then
		echo "FAIL: ${name}: expected a non-zero exit status" >&2
		exit 1
	fi

	echo "ok: ${name} (exit ${status})"
}

# The script hashes raw bytes, so these need not be real DER files.
printf '' >"${workdir}/empty.bin"
printf 'abc' >"${workdir}/abc.bin"
printf 'balena cert-manager keyid test vector\n' >"${workdir}/text.bin"

check 'empty input' \
	'4OYM:IQUY:7QOB:JGX3:6TEJ:S35Z:EQT2:4QPE:MSNZ:GTFE:SWMR:W6CS' \
	"$(/opt/_keyid.sh "${workdir}/empty.bin")"

check 'abc' \
	'XJ4B:NP4P:AHH6:UQKB:IDPF:3LRC:EOYA:GYND:SYLX:VHFU:CD7W:D4QA' \
	"$(/opt/_keyid.sh "${workdir}/abc.bin")"

check 'text' \
	'BNRI:BHGU:UL4X:FQKY:UXYY:JYHH:CB5B:5Y7R:PUSK:YR2P:44IK:YVWM' \
	"$(/opt/_keyid.sh "${workdir}/text.bin")"

# A real P-256 SPKI, derived as compute_api_kid() in entry.sh does.
cat >"${workdir}/api.key" <<'EOF'
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIExEXDNy5EKkx7gWDtVgmXbCkf4M3Ydxzj8BHeyG+vuxoAoGCCqGSM49
AwEHoUQDQgAEoAgYRVMCp7YEhMxyzTowzfZN4kumPUOXm5o7Ax69MJ4MlR+Y++1g
9OSq83/VxwvJS8twwM2JyXO7pSvXbesDGg==
-----END EC PRIVATE KEY-----
EOF

openssl ec \
	-in "${workdir}/api.key" \
	-pubout \
	-outform DER \
	-out "${workdir}/api.der" 2>/dev/null

expected_kid='WTJJ:7VBC:34AL:6NG2:C26V:BF5U:ELFU:64W7:B4GN:5F55:JPEA:CT2U'

check 'P-256 public key DER' "${expected_kid}" "$(/opt/_keyid.sh "${workdir}/api.der")"

# A different kid for an unchanged key would break token auth.
check 'deterministic' "${expected_kid}" "$(/opt/_keyid.sh "${workdir}/api.der")"

# 30 bytes is 48 base32 characters: 12 groups of 4, no padding.
if [[ ! ${expected_kid} =~ ^([A-Z2-7]{4}:){11}[A-Z2-7]{4}$ ]]; then
	echo "FAIL: key ID format regex is wrong" >&2
	exit 1
fi

if [[ ! "$(/opt/_keyid.sh "${workdir}/api.der")" =~ ^([A-Z2-7]{4}:){11}[A-Z2-7]{4}$ ]]; then
	echo "FAIL: key ID is not 12 groups of 4 base32 characters" >&2
	exit 1
fi

echo "ok: key ID format"

# entry.sh writes this straight into the .kid file. Command substitution
# strips trailing newlines, so a sentinel is needed to see the raw bytes.
check 'no trailing newline' \
	"${expected_kid}X" \
	"$(
		/opt/_keyid.sh "${workdir}/api.der"
		printf 'X'
	)"

check_fails 'missing file' /opt/_keyid.sh "${workdir}/does-not-exist.der"
check_fails 'no arguments' /opt/_keyid.sh
check_fails 'too many arguments' /opt/_keyid.sh "${workdir}/api.der" "${workdir}/abc.bin"

echo "Key ID derivation verified."
