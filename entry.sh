#!/usr/bin/env bash

set -exa

CERTS=${CERTS:-/certs}
EXPORT_CERT_CHAIN_PATH=${EXPORT_CERT_CHAIN_PATH:-${CERTS}/export/chain.pem}
SUBJECT_ALTERNATE_NAMES=${SUBJECT_ALTERNATE_NAMES:-*,*.devices,*.s3,*.img}
SSH_KEY_NAMES=${SSH_KEY_NAMES:-devices,git,proxy}
ca_http_url=${CA_HTTP_URL:-http://balena-ca:8888}
attempts=${ATTEMPTS:-5}
country=${COUNTRY:-US}
state=${STATE:-Washington}
locality_name=${LOCALITY_NAME:-Seattle}
org=${ORG:-balena}
org_unit=${ORG_UNIT:-balenaCloud}
key_algo=${KEY_ALGO:-ecdsa}
key_size=${KEY_SIZE:-256}

if [[ -n "${BALENA_DEVICE_UUID}" ]]; then
    # prepend the device UUID if running on balenaOS
    # shellcheck disable=SC2153
    TLD="${BALENA_DEVICE_UUID}.${DNS_TLD}"
else
    TLD="${DNS_TLD}"
fi

rm -f "${CERTS}/.ready"

function compute_api_kid {
    local tld
    tld="${1}"
    [[ -n "${tld}" ]] || return

    if [[ -f "${CERTS}/private/api.${tld}.key" ]]; then
        openssl ec \
          -in "${CERTS}/private/api.${tld}.key" \
          -pubout \
          -outform DER \
          -out "${CERTS}/private/api.${tld}.der"
    fi

    if [[ -f "${CERTS}/private/api.${tld}.der" ]]; then
        # https://github.com/balena-io/open-balena/blob/master/scripts/gen-token-auth-cert
        node --no-deprecation /opt/_keyid.js \
          "${CERTS}/private/api.${tld}.der" \
          > "${CERTS}/private/api.${tld}.kid"
    fi
}

function generate_vpn_dhparams {
    local tld
    tld="${1}"
    [[ -n "${tld}" ]] || return

    if ! [[ -f "${CERTS}/private/dhparam.${tld}.pem" ]]; then
        openssl dhparam -out "${CERTS}/private/dhparam.${tld}.pem" 2048
    fi
}

function generate_ssh_keys {
    local cn
    cn="${1}"
    [[ -n "${cn}" ]] || return

    local tld
    tld="${2}"
    [[ -n "${tld}" ]] || return

    if [[ -d "${CERTS}/private" ]]; then
        # (DSA) https://security.stackexchange.com/a/112818/201462
        for algo in rsa ecdsa dsa ed25519; do
            key="${CERTS}/private/${cn}.${tld}.${algo}.key"
            if ! [[ -f "${key}" ]]; then
                # cfssl doesn't handle dsa and ed25519 key formats
                ssh-keygen -f "${key}" -t "${algo}" -N "" -m PEM \
                  && chmod 0600 "${key}"
            fi
            ssh-keygen -y -f "${key}" > "${key}.pub"
        done
    fi

    find "${CERTS}/private" \
      -name "${cn}.${tld}.*.key.pub" \
      -exec cat {} \; > "${CERTS}/private/${cn}.${tld}.authorized_keys"
}

function get_acme_email {
    local balena_device_uuid
    balena_device_uuid="${1}"
    [[ -n "${balena_device_uuid}" ]] || return

    if [[ -n "${ACME_EMAIL}" ]]; then
        acme_email="${ACME_EMAIL}"
    else
        # shellcheck disable=SC2153
        acme_email="$(curl --retry "${attempts}" --fail "${BALENA_API_URL}/user/v1/whoami" \
          -H "Content-Type: application/json" \
          -H "Authorization: Bearer $(get_env_var_value "${balena_device_uuid}" API_TOKEN)" \
          --compressed | jq -r '.email')"
    fi
    echo "${acme_email}"
}

function get_env_var_value {
    local balena_device_uuid
    balena_device_uuid="${1}"
    [[ -n "${balena_device_uuid}" ]] || return

    local varname
    varname="${2}"
    [[ -n "${varname}" ]] || return


    local varval
    varval=${!varname}

    if [[ -z "$varval" ]]; then
        balena_device_id="$(curl --retry "${attempts}" --fail \
          "${BALENA_API_URL}/v6/device?\$filter=uuid%20eq%20'${balena_device_uuid}'" \
          -H "Content-Type: application/json" \
          -H "Authorization: Bearer ${BALENA_API_KEY}" \
          --compressed | jq -r .d[].id)"

        varval="$(curl --retry "${attempts}" --fail \
          "${BALENA_API_URL}/v6/device_service_environment_variable?\$filter=service_install/device%20eq%20${balena_device_id}" \
          -H "Content-Type: application/json" \
          -H "Authorization: Bearer ${BALENA_API_KEY}" \
          --compressed \
          | jq -r --arg varname "${varname}" '.d[] | select(.name==$varname).value')"
    fi
    echo "${varval}"
}

function cloudflare_issue_public_cert {
    local balena_device_uuid
    balena_device_uuid="${1}"
    [[ -n "${balena_device_uuid}" ]] || return

    local dns_tld
    dns_tld="${2}"
    [[ -n "${dns_tld}" ]] || return

    cloudflare_api_token="$(get_env_var_value "${balena_device_uuid}" CLOUDFLARE_API_TOKEN)"
    [[ -n "${cloudflare_api_token}" ]] || return

    mkdir -p ~/.secrets/certbot

    echo "dns_cloudflare_api_token = ${cloudflare_api_token}" \
      > ~/.secrets/certbot/cloudflare.ini \
      && chmod 0600 ~/.secrets/certbot/cloudflare.ini

    # shellcheck disable=SC2086
    certbot certonly --agree-tos --non-interactive --verbose --expand \
      --dns-cloudflare \
      --dns-cloudflare-credentials ~/.secrets/certbot/cloudflare.ini \
      -m "$(get_acme_email ${balena_device_uuid})" \
      -d "${dns_tld}" \
      -d "*.${dns_tld}" \
      ${sans}
}

function gandi_issue_public_cert {
    local balena_device_uuid
    balena_device_uuid="${1}"
    [[ -n "${balena_device_uuid}" ]] || return

    local dns_tld
    dns_tld="${2}"
    [[ -n "${dns_tld}" ]] || return

    gandi_api_token="$(get_env_var_value "${balena_device_uuid}" GANDI_API_TOKEN)"
    [[ -n "${gandi_api_token}" ]] || return

    mkdir -p ~/.secrets/certbot

    echo "dns_gandi_api_key = ${gandi_api_token}" \
      > ~/.secrets/certbot/gandi.ini \
      && chmod 0600 ~/.secrets/certbot/gandi.ini

    # https://github.com/obynio/certbot-plugin-gandi
    pip install certbot-plugin-gandi

    # shellcheck disable=SC2086
    certbot certonly --agree-tos --non-interactive --verbose --expand \
      --authenticator dns-gandi \
      --dns-gandi-credentials ~/.secrets/certbot/gandi.ini \
      -m "$(get_acme_email ${balena_device_uuid})" \
      -d "${dns_tld}" \
      -d "*.${dns_tld}" \
      ${sans}
}

function issue_public_certs {
    local balena_device_uuid
    balena_device_uuid="${1}"
    [[ -n "${balena_device_uuid}" ]] || return

    local dns_tld
    dns_tld="${2}"
    [[ -n "${dns_tld}" ]] || return

    local tld
    tld="${3}"
    [[ -n "${tld}" ]] || return

    if ! [[ $dns_tld =~ ^.*\.local\.? ]]; then
        # chain breaks after first success
        cloudflare_issue_public_cert "${balena_device_uuid}" "${dns_tld}" \
          || gandi_issue_public_cert "${balena_device_uuid}" "${dns_tld}" \
          || true

        if [[ -f "live/${dns_tld}/fullchain.pem" ]] \
          && [[ -f "live/${dns_tld}/privkey.pem" ]]; then
            # only update if renewed
            if ! diff "live/${dns_tld}/fullchain.pem" \
              "${CERTS}/public/${tld}.pem"; then
                cat < "live/${dns_tld}/fullchain.pem" \
                  > "${CERTS}/public/${tld}.pem"
            fi

            if ! diff "live/${dns_tld}/privkey.pem" \
              "${CERTS}/public/${tld}.key"; then
                cat < "live/${dns_tld}/privkey.pem" \
                  > "${CERTS}/public/${tld}.key"
            fi

            tmpchain="$(mktemp)"

            if ! diff "live/${dns_tld}/fullchain.pem" \
              "live/${dns_tld}/privkey.pem"; then
                cat "live/${dns_tld}/fullchain.pem" \
                  "live/${dns_tld}/privkey.pem" > "${tmpchain}"
            fi

            if ! diff "${tmpchain}" "${CERTS}/public/${tld}-chain.pem"; then
                cat "live/${dns_tld}/fullchain.pem" \
                  "live/${dns_tld}/privkey.pem" \
                  > "${CERTS}/public/${tld}-chain.pem"
            fi

            rm -f "${tmpchain}"
        fi
    fi
}

function issue_private_certs {
    local requests_certs
    requests_certs="${1}"
    [[ -f "${requests_certs}" ]] || return

    # https://www.starkandwayne.com/blog/bash-for-loop-over-json-array-using-jq/
    for request in $(cat < "${requests_certs}" | jq -r '.[] | @base64'); do
        _jq() {
            echo "${request}" | base64 -d | jq -r "${1}"
        }
        tmprequest="$(mktemp)"
        _jq '.' > "${tmprequest}"
        common_name="$(_jq '.request.CN')"

        if ! [[ -f "${CERTS}/private/${common_name}.pem" ]]; then
            cat < "${tmprequest}" | jq -r

            response="$(curl --retry "${attempts}" --fail \
              "${ca_http_url}/api/v1/cfssl/newcert" \
              --data @"${tmprequest}")"

            echo "${response}" | jq -r '.result.certificate' > "${CERTS}/private/${common_name}.pem"
            echo "${response}" | jq -r '.result.private_key' > "${CERTS}/private/${common_name}.key"
            chmod 0600 "${CERTS}/private/${common_name}.key"
        fi
        rm -f "${tmprequest}"
    done
}

function issue_private_keys {
    local requests_keys
    requests_keys="${1}"
    [[ -f "${requests_keys}" ]] || return

    for request in $(cat < "${requests_keys}" | jq -r '.[] | @base64'); do
        _jq() {
            echo "${request}" | base64 -d | jq -r "${1}"
        }
        tmprequest="$(mktemp)"
        _jq '.' > "${tmprequest}"
        common_name="$(_jq '.CN')"

        if ! [[ -f "${CERTS}/private/${common_name}.key" ]]; then
            cat < "${tmprequest}" | jq -r

            response="$(curl --retry "${attempts}" --fail \
              "${ca_http_url}/api/v1/cfssl/newkey" \
              --data @"${tmprequest}")"

            echo "${response}" | jq -r '.result.private_key' > "${CERTS}/private/${common_name}.key"
            chmod 0600 "${CERTS}/private/${common_name}.key"
        fi
        rm -f "${tmprequest}"
    done
}

function generate_compute_all {
    local tld
    tld="${1}"
    [[ -n "${tld}" ]] || return

    compute_api_kid "${tld}"
    generate_vpn_dhparams "${tld}"

    ssh_key_names=($(echo "${SSH_KEY_NAMES}" | tr ',' ' '))
    for kn in ${ssh_key_names[*]}; do
        generate_ssh_keys "${kn}" "${tld}"
    done
}

function resolve_cert_target {
    local tld
    tld="${1}"
    [[ -n "${tld}" ]] || return

    local target
    target=private

    if [[ -f "${CERTS}/public/${tld}.pem" ]] \
      && [[ -f "${CERTS}/public/${tld}.key" ]]; then
        target=public
    fi

    echo "${target}"
}

function surface_resolved_cert_chain {
    local tld
    tld="${1}"
    [[ -n "${tld}" ]] || return

    target="$(resolve_cert_target "${tld}")"
    for cert in "${tld}.pem" \
      "${tld}.key" \
      "${tld}-chain.pem"; do
        # shellcheck disable=SC2235
        if ! [[ -L "${CERTS}/${cert}" ]] \
          || (! [[ "$(readlink -f "${CERTS}/${cert}")" =~ ${CERTS}\/${target}\/ ]]) \
          && [[ -f "${CERTS}/${target}/${cert}" ]]; then
            rm -f "${CERTS}/${cert}"
            ln -s "${CERTS}/${target}/${cert}" "${CERTS}/${cert}"
        fi
    done

    # shellcheck disable=SC2235
    if (! [[ -L "${EXPORT_CERT_CHAIN_PATH}" ]] \
      || ! [[ "$(readlink -f "${EXPORT_CERT_CHAIN_PATH}")" =~ ${CERTS}\/${target}\/ ]]) \
      && [[ -f "${CERTS}/${target}/${tld}-chain.pem" ]]; then
        rm -f "${EXPORT_CERT_CHAIN_PATH}"
        ln -s "${CERTS}/${target}/${tld}-chain.pem" "${EXPORT_CERT_CHAIN_PATH}"
    fi
}

# (TBC) handle renewals
function assemble_private_cert_chain {
    local tld
    tld="${1}"
    [[ -n "${tld}" ]] || return

    if ! [[ -f "${CERTS}/private/${tld}-chain.pem" ]]; then
        cat "${CERTS}/private/${tld}.pem" \
          "${CERTS}/private/server-ca.${tld}.pem" \
          "${CERTS}/private/root-ca.${tld}.pem" \
          "${CERTS}/private/${tld}.key" \
          > "${CERTS}/private/${tld}-chain.pem"
    fi
}

function surface_root_certs {
    local tld
    tld="${1}"
    [[ -n "${tld}" ]] || return

    for cert in ca-bundle server-ca root-ca; do
        if ! [[ -L "${CERTS}/${cert}.pem" ]] \
          && [[ -f "${CERTS}/private/${cert}.${tld}.pem" ]]; then
            ln -s "${CERTS}/private/${cert}.${tld}.pem" "${CERTS}/${cert}.pem"
        fi
    done
}

function resolve_sans {
    # https://stackoverflow.com/a/11456496/1559300
    set -f
    local tld
    tld="${1}"
    [[ -n "${tld}" ]] || return
    local subject_alternate_names
    subject_alternate_names="${2}"
    [[ -n "${subject_alternate_names}" ]] || return
    local arr
    arr=("${subject_alternate_names//,/ }")
    local sans
    sans="$(for san in ${arr[*]}; do echo "-d ${san}.${tld}"; done)"
    echo "${sans}"
    set +f
}

function resolve_hosts {
    set -f
    local dns_tld
    dns_tld="${1}"
    [[ -n "${dns_tld}" ]] || return
    local tld
    tld="${2}"
    [[ -n "${tld}" ]] || return
    local subject_alternate_names
    subject_alternate_names="${3}"
    [[ -n "${subject_alternate_names}" ]] || return
    local arr
    arr=("${subject_alternate_names//,/ }")
    local hosts
    hosts="$(for san in ${arr[*]}; do printf '%s.%s\n%s.%s\n' "${san}" "${tld}" "${san}" "${dns_tld}"; done | tr '\n' ',')"
    echo "${hosts}"
    set +f
}

function get_server_ca {
    local tld
    tld="${1}"
    [[ -n "${tld}" ]] || return

    # shellcheck disable=SC2153
    if ! [[ -f "${CERTS}/private/server-ca.${tld}.pem" ]]; then
        curl --retry "${attempts}" --fail "${ca_http_url}/api/v1/cfssl/info" \
          --data '{"label": "primary"}' \
          | jq -r '.result.certificate' > "${CERTS}/private/server-ca.${tld}.pem"
    fi
}

function get_root_ca {
    local tld
    tld="${1}"
    [[ -n "${tld}" ]] || return

    # shellcheck disable=SC2153
    if ! [[ -f "${CERTS}/private/root-ca.${tld}.pem" ]]; then
        curl --retry "${attempts}" --fail "${ca_http_url}/api/v1/cfssl/bundle" \
          --data "{\"certificate\": \"$(cat < "${CERTS}/private/server-ca.${tld}.pem" | awk '{printf "%s\\n", $0}')\"}" \
          | jq -r '.result.root' > "${CERTS}/private/root-ca.${tld}.pem"
    fi
}

function resolve_templates() {
    local tmptmpl="$(mktemp)"
    if [[ -f $1 ]]; then
        cat "$1" | envsubst > "${tmptmpl}"
    else
        echo '[]' > "${tmptmpl}"
    fi
    echo "${tmptmpl}"
}

mkdir -p "${CERTS}/public" "${CERTS}/private" "$(dirname "${EXPORT_CERT_CHAIN_PATH}")"

while ! curl -I --fail "${ca_http_url}"; do sleep "$((RANDOM%10+1))s"; done

get_server_ca "${TLD}"
get_root_ca "${TLD}"

hosts="$(resolve_hosts "${DNS_TLD}" "${TLD}" "${SUBJECT_ALTERNATE_NAMES}")"
hosts="$(jq -c -n --arg hosts "${hosts::-1}" '$hosts | split(",")')"
sans="$(resolve_sans "${TLD}" "${SUBJECT_ALTERNATE_NAMES}")"

# generate cryptographic assets
issue_private_certs "$(resolve_templates /opt/certs.json)"
issue_private_keys "$(resolve_templates /opt/keys.json)"
issue_public_certs "${BALENA_DEVICE_UUID}" "${DNS_TLD}" "${TLD}"
surface_root_certs "${TLD}"
generate_compute_all "${TLD}"
assemble_private_cert_chain "${TLD}"
surface_resolved_cert_chain "${TLD}"

# signal healthy
touch "${CERTS}/.ready"

# (TBC) exit-restart in 7 days and check for renewal (LetEncrypt only)
sleep 7d
