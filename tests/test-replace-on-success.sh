#!/usr/bin/env bash

# Tests replace_on_success() from entry.sh, extracted from the installed copy
# so this covers shipped code. A plain redirection truncates its target before
# the command runs, destroying the last good .kid or .jwks.json on failure.

set -eo pipefail

entry='/usr/local/bin/entry.sh'

if [[ ! -r ${entry} ]]; then
	echo "FAIL: cannot read ${entry}" >&2
	exit 1
fi

definition="$(sed -n '/^function replace_on_success/,/^}$/p' "${entry}")"

if [[ -z ${definition} ]]; then
	echo "FAIL: replace_on_success() not found in ${entry}" >&2
	exit 1
fi

eval "${definition}"

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

function count_files {
	local dir
	dir="${1}"

	find "${dir}" -maxdepth 1 -type f | wc -l | tr -d ' '
}

target="${workdir}/api.kid"

# Success writes stdout to the target.
replace_on_success "${target}" echo 'first value'
check 'writes on success' 'first value' "$(cat "${target}")"
check 'no temporary left behind' '1' "$(count_files "${workdir}")"

# Other containers share ${CERTS}, so keep the permissions a redirect gives.
: >"${workdir}/reference"
check 'permissions match a redirect' \
	"$(stat -c %a "${workdir}/reference")" \
	"$(stat -c %a "${target}")"
rm -f "${workdir}/reference"

# Failure must leave the previous content untouched.
status=0
replace_on_success "${target}" false || status="${?}"

check 'returns non-zero on failure' '1' "${status}"
check 'keeps the previous value' 'first value' "$(cat "${target}")"
check 'no temporary left after failure' '1' "$(count_files "${workdir}")"

# Partial output from a failing command must not be promoted.
status=0
replace_on_success "${target}" bash -c 'echo partial; exit 1' || status="${?}"

check 'returns non-zero on partial output' '1' "${status}"
check 'partial output discarded' 'first value' "$(cat "${target}")"

# Success replaces the previous content.
replace_on_success "${target}" echo 'second value'
check 'replaces on success' 'second value' "$(cat "${target}")"

# Failure must not create a target that did not exist.
missing="${workdir}/never-written"
status=0
replace_on_success "${missing}" false || status="${?}"

check 'failure creates no target' '1' "${status}"

if [[ -e ${missing} ]]; then
	echo "FAIL: ${missing} was created by a failing command" >&2
	exit 1
fi

echo "ok: failing command leaves no target file"
echo "replace_on_success verified."
