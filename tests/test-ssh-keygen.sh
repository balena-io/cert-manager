#!/usr/bin/env bash

# Verifies that ssh-keygen in the built image still supports every algorithm
# referenced by generate_ssh_keys() in entry.sh. A base-image bump that drops
# support for an algorithm (as happened with DSA) will fail this test.

set -eo pipefail

ENTRY_SH="${ENTRY_SH:-/usr/local/bin/entry.sh}"

if [[ ! -s "${ENTRY_SH}" ]]; then
	echo "FAIL: ${ENTRY_SH} not found in image" >&2
	exit 1
fi

# Extract the algorithm list from entry.sh's `for algo in <...>; do` loop so
# this test stays in sync with production without duplicating the list.
algos=$(sed -n 's/.*for algo in \(.*\); do.*/\1/p' "${ENTRY_SH}")

if [[ -z "${algos}" ]]; then
	echo "FAIL: could not extract algorithm list from ${ENTRY_SH}" >&2
	exit 1
fi

echo "Testing ssh-keygen for algorithms: ${algos}"

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

for algo in ${algos}; do
	key="${workdir}/test.${algo}.key"

	if ! ssh-keygen -f "${key}" -t "${algo}" -N "" -m PEM >/dev/null; then
		echo "FAIL: ssh-keygen does not support -t ${algo}" >&2
		exit 1
	fi

	if [[ ! -s "${key}" ]]; then
		echo "FAIL: private key not produced for ${algo}" >&2
		exit 1
	fi

	if ! ssh-keygen -y -f "${key}" >"${key}.pub"; then
		echo "FAIL: ssh-keygen -y failed for ${algo}" >&2
		exit 1
	fi

	if [[ ! -s "${key}.pub" ]]; then
		echo "FAIL: public key not produced for ${algo}" >&2
		exit 1
	fi

	echo "ok: ${algo}"
done

echo "All algorithms supported."
