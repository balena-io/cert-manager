#!/usr/bin/env bash

# The eMudhra CA key compromise is addressed by the NSS release in
# ca-certificates 20261020-r0. The Dockerfile asks for '>=' that version so the
# build keeps working as Alpine publishes newer ones; this test fails if the
# base image ever resolves something older.

set -eo pipefail

floor='20261020-r0'

function check_floor {
	local pkg installed relation
	pkg="${1}"

	installed="$(apk info -v | grep -x "${pkg}-[0-9].*" || true)"
	installed="${installed#"${pkg}-"}"

	if [[ -z ${installed} ]]; then
		echo "FAIL: ${pkg} is not installed" >&2
		exit 1
	fi

	# apk compares the versions itself, so this needs no parsing.
	relation="$(apk version -t "${installed}" "${floor}")"

	if [[ ${relation} == '<' ]]; then
		echo "FAIL: ${pkg} ${installed} is older than ${floor}" >&2
		exit 1
	fi

	echo "ok: ${pkg} ${installed} (${relation} ${floor})"
}

# The roots ship in the bundle subpackage, and neither package depends on the
# other, so both are checked.
check_floor ca-certificates
check_floor ca-certificates-bundle

echo "Trust store version verified."
