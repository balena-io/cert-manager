#!/usr/bin/env bash

set -ea

[[ "${VERBOSE}" =~ on|On|Yes|yes|true|True ]] && set -x

if [[ -n $BALENA_DEVICE_UUID ]]; then
    # prepend the device UUID if running on balenaOS
    TLD="${TLD:-${BALENA_DEVICE_UUID}.${DNS_TLD}}"
else
    TLD="${TLD:-${DNS_TLD}}"
fi

AWS_S3_ENDPOINT=${AWS_S3_ENDPOINT:-https://s3.amazonaws.com}
AWS_REGION=${AWS_REGION:-us-east-1}
AWS_DEFAULT_REGION=${AWS_REGION}
CERTS=${CERTS:-/certs}
EXPORT_CERT_CHAIN_PATH=${EXPORT_CERT_CHAIN_PATH:-${CERTS}/export/chain.pem}
SUBJECT_ALTERNATE_NAMES=${SUBJECT_ALTERNATE_NAMES:-*,*.devices,*.s3,*.img}
SSH_KEY_NAMES=${SSH_KEY_NAMES:-devices,git,proxy}
ca_http_url=${CA_HTTP_URL:-http://balena-ca:8888}
dns_cloudflare_propagation_seconds=${DNS_CLOUDFLARE_PROPAGATION_SECONDS:-60}
attempts=${ATTEMPTS:-3}
timeout=${TIMEOUT:-60}
cert_seconds_until_expiry=${CERT_SECONDS_UNTIL_EXPIRY:-604800} # 7 days

# shellcheck disable=SC2034
country=${COUNTRY:-US}
# shellcheck disable=SC2034
state=${STATE:-Washington}
# shellcheck disable=SC2034
locality_name=${LOCALITY_NAME:-Seattle}
# shellcheck disable=SC2034
org=${ORG:-balena}
# shellcheck disable=SC2034
org_unit=${ORG_UNIT:-balenaCloud}
# shellcheck disable=SC2034
key_algo=${KEY_ALGO:-ecdsa}
# shellcheck disable=SC2034
key_size=${KEY_SIZE:-256}

function cleanup() {
   remove_update_lock
   sleep $(( (RANDOM % 5) + 5))s
}
trap 'cleanup' EXIT

# https://coderwall.com/p/--eiqg/exponential-backoff-in-bash
# https://letsencrypt.org/docs/integration-guide/#retrying-failures
function with_backoff() {
    local max_attempts=${attempts-5}
    local timeout=${timeout-1}
    local attempt=0
    local exitCode=0

    set +e
    while [[ $attempt < $max_attempts ]]
    do
        "$@"
        exitCode=$?

        if [[ $exitCode == 0 ]]
        then
          break
        fi

        echo "Failure! Retrying in $timeout.." 1>&2
        sleep "$timeout"
        attempt=$(( attempt + 1 ))
        timeout=$(( timeout * 2 ))
    done

    if [[ $exitCode != 0 ]]
    then
        echo "You've failed me for the last time! ($*)" 1>&2
    fi

    set -e
    return $exitCode
}

function compute_api_kid {
    local tld
    tld="${1}"
    [[ -n "${tld}" ]] || return

    if [[ -s "${CERTS}/private/api.${tld}.key" ]]; then
        openssl ec \
          -in "${CERTS}/private/api.${tld}.key" \
          -pubout \
          -outform DER \
          -out "${CERTS}/private/api.${tld}.der"
    fi

    if [[ -s "${CERTS}/private/api.${tld}.der" ]]; then
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

    if ! [[ -s "${CERTS}/private/dhparam.${tld}.pem" ]]; then
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
            if ! [[ -s "${key}" ]]; then
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
    if [[ -n $ACME_EMAIL ]]; then
        acme_email="${ACME_EMAIL}"
    else
        if [[ -n $BALENA_API_URL ]]; then
            local balena_device_uuid
            balena_device_uuid="${1}"
            [[ -n "${balena_device_uuid}" ]] || return

            # shellcheck disable=SC2153
            acme_email="$(curl --retry "${attempts}" --fail "${BALENA_API_URL}/user/v1/whoami" \
              -H "Content-Type: application/json" \
              -H "Authorization: Bearer $(get_env_var_value "${balena_device_uuid}" API_TOKEN)" \
              --compressed | jq -r '.email')"
        fi
    fi
    echo "${acme_email}"
}

function get_env_var_value {
    local varname
    varname="${2}"
    [[ -n "${varname}" ]] || return

    local varval
    varval=${!varname}

    if [[ -z "$varval" ]]; then
        if [[ -n $BALENA_API_URL ]] && [[ -n $BALENA_API_KEY ]]; then
            local balena_device_uuid
            balena_device_uuid="${1}"
            [[ -n "${balena_device_uuid}" ]] || return

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
    fi
    echo "${varval}"
}

function hetzner_issue_public_cert {
    local balena_device_uuid
    balena_device_uuid="${1}"

    local dns_tld
    dns_tld="${2}"
    [[ -n "${dns_tld}" ]] || return

    hetzner_api_token="$(get_env_var_value "${balena_device_uuid}" HETZNER_API_TOKEN)"
    [[ -n "${hetzner_api_token}" ]] || return

    mkdir -p ~/.secrets/certbot

    echo "dns_hetzner_api_token = ${hetzner_api_token}" \
      > ~/.secrets/certbot/hetzner.ini \
      && chmod 0600 ~/.secrets/certbot/hetzner.ini

    # Install the Hetzner DNS plugin for Certbot
    pip install certbot-dns-hetzner

    # shellcheck disable=SC2086
    with_backoff certbot certonly --agree-tos --non-interactive --verbose --expand \
      --authenticator dns-hetzner \
      --dns-hetzner-credentials ~/.secrets/certbot/hetzner.ini \
      --dns-hetzner-propagation-seconds 60 \
      --cert-name "${dns_tld}" \
      -m "$(get_acme_email ${balena_device_uuid})" \
      -d "${dns_tld}" \
      ${sans}
}

function cloudflare_issue_public_cert {
    local balena_device_uuid
    balena_device_uuid="${1}"

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
    with_backoff certbot certonly --agree-tos --non-interactive --verbose --expand \
      --dns-cloudflare \
      --dns-cloudflare-propagation-seconds "${dns_cloudflare_propagation_seconds}" \
      --dns-cloudflare-credentials ~/.secrets/certbot/cloudflare.ini \
      --cert-name "${dns_tld}" \
      -m "$(get_acme_email ${balena_device_uuid})" \
      -d "${dns_tld}" \
      ${sans}
}

function gandi_issue_public_cert {
    local balena_device_uuid
    balena_device_uuid="${1}"

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
    with_backoff certbot certonly --agree-tos --non-interactive --verbose --expand \
      --authenticator dns-gandi \
      --dns-gandi-credentials ~/.secrets/certbot/gandi.ini \
      --cert-name "${dns_tld}" \
      -m "$(get_acme_email ${balena_device_uuid})" \
      -d "${dns_tld}" \
      ${sans}
}

function s3_init() {
    if [[ -n $AWS_ACCESS_KEY_ID ]] && [[ -n $AWS_SECRET_ACCESS_KEY ]]; then
        mcli alias set s3 "${AWS_S3_ENDPOINT}" "${AWS_ACCESS_KEY_ID}" "${AWS_SECRET_ACCESS_KEY}"
    else
        false
    fi
}

function backup_certs_to_s3 {
    local dns_tld
    dns_tld="${1}"

    if [[ -n $AWS_S3_BUCKET ]]; then
        tar -cpvzf "/tmp/${dns_tld}.tgz" --exclude='accounts' --exclude='renewal-hooks' *
        (s3_init && mcli cp --recursive "/tmp/${dns_tld}.tgz" "s3/${AWS_S3_BUCKET}/") || true
        rm -f "/tmp/${dns_tld}.tgz"
    fi
}

function restore_certs_from_s3 {
    local dns_tld
    dns_tld="${1}"

    if [[ -n $AWS_S3_BUCKET ]]; then
        (s3_init && mcli cp --recursive "s3/${AWS_S3_BUCKET}/${dns_tld}.tgz" /tmp) || true

        if [[ -e /tmp/$dns_tld.tgz ]]; then
            tar -xvf "/tmp/${dns_tld}.tgz"
            rm -f "/tmp/${dns_tld}.tgz"
        fi
    fi
}

function issue_public_certs {
    local balena_device_uuid
    balena_device_uuid="${1}"

    local dns_tld
    dns_tld="${2}"
    [[ -n "${dns_tld}" ]] || return

    local tld
    tld="${3}"
    [[ -n "${tld}" ]] || return

    if ! [[ $dns_tld =~ ^.*\.local\.? ]]; then
        restore_certs_from_s3 "${dns_tld}"

        current="$(ls -dt live/${dns_tld}* | head -n1)"

        # only attempt to renew if the certificate is near expiry
        if ! check_cert_expiry "${current}/cert.pem"; then
            # chain breaks after first success
            cloudflare_issue_public_cert "${balena_device_uuid}" "${dns_tld}" \
              || gandi_issue_public_cert "${balena_device_uuid}" "${dns_tld}" \
              || hetzner_issue_public_cert "${balena_device_uuid}" "${dns_tld}" \
              || true
        fi

        # refresh link to the latest certificate set
        # https://community.letsencrypt.org/t/prevent-0001-xxxx-certificate-suffixes/66802/3
        # https://community.letsencrypt.org/t/re-prevent-0001-xxxx-certificate-suffixes/83824
        # shellcheck disable=SC2012
        # shellcheck disable=SC2086
        if [[ -d live ]]; then
            rm -f live/latest
            current="$(ls -dt live/${dns_tld}* | head -n1)"
            if [[ -n $current ]]; then
                ln -fs "../${current}" live/latest
            fi

            backup_certs_to_s3 "${dns_tld}"
        fi

        if [[ -s "live/latest/fullchain.pem" ]] && [[ -s "live/latest/privkey.pem" ]]; then
            # only update if renewed
            if ! diff "live/latest/fullchain.pem" \
              "${CERTS}/public/${tld}.pem"; then
                cat < "live/latest/fullchain.pem" > "${CERTS}/public/${tld}.pem"
            fi

            if ! diff "live/latest/privkey.pem" \
              "${CERTS}/public/${tld}.key"; then
                cat < "live/latest/privkey.pem" > "${CERTS}/public/${tld}.key"
            fi

            tmpchain="$(mktemp)"

            if ! diff "live/latest/fullchain.pem" \
              "live/latest/privkey.pem"; then
                cat "live/latest/fullchain.pem" "live/latest/privkey.pem" > "${tmpchain}"
            fi

            if ! diff "${tmpchain}" "${CERTS}/public/${tld}-chain.pem"; then
                cat "live/latest/fullchain.pem" "live/latest/privkey.pem" \
                  > "${CERTS}/public/${tld}-chain.pem"
            fi

            rm -f "${tmpchain}"
        fi
    fi
}

function issue_private_certs {
    local requests_certs
    requests_certs="${1}"
    [[ -s "${requests_certs}" ]] || return

    # https://www.starkandwayne.com/blog/bash-for-loop-over-json-array-using-jq/
    for request in $(cat < "${requests_certs}" | jq -r '.[] | @base64'); do
        _jq() {
            echo "${request}" | base64 -d | jq -r "${1}"
        }
        tmprequest="$(mktemp)"
        _jq '.' > "${tmprequest}"
        common_name="$(_jq '.request.CN')"

        if ! [[ -s "${CERTS}/private/${common_name}.pem" ]]; then
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
    [[ -s "${requests_keys}" ]] || return

    for request in $(cat < "${requests_keys}" | jq -r '.[] | @base64'); do
        _jq() {
            echo "${request}" | base64 -d | jq -r "${1}"
        }
        tmprequest="$(mktemp)"
        _jq '.' > "${tmprequest}"
        common_name="$(_jq '.CN')"

        if ! [[ -s "${CERTS}/private/${common_name}.key" ]]; then
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

    # shellcheck disable=SC2207
    ssh_key_names=($(echo "${SSH_KEY_NAMES}" | tr ',' ' '))
    # shellcheck disable=SC2048
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

    if [[ -s "${CERTS}/public/${tld}.pem" ]] \
      && [[ -s "${CERTS}/public/${tld}.key" ]]; then
        target=public
    fi

    echo "${target}"
}

# ensure certificate chain at the well-known location is up to date
# .. don't touch customer supplied certificates managed by HAProxy
# .. only work on certificates issued by self-signed server CA
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
          && [[ -s "${CERTS}/${target}/${cert}" ]]; then
            rm -f "${CERTS}/${cert}"
            ln -s "${CERTS}/${target}/${cert}" "${CERTS}/${cert}"
        fi
    done

    # shellcheck disable=SC2235
    if [[ -s "$EXPORT_CERT_CHAIN_PATH" ]] && [[ -s "${CERTS}/${target}/${tld}-chain.pem" ]]; then
        cert_issuer="$(get_cert_issuer "${EXPORT_CERT_CHAIN_PATH}" | awk -F'issuer=' '{print $2}')"
        server_ca="$(get_cert_subject "${CERTS}/server-ca.pem" | awk -F'subject=' '{print $2}')"

        custom_cert=1
        if [[ "$cert_issuer" =~ "$server_ca" ]]; then
            custom_cert=0
        fi

        update_link=0
        if [[ ! -L "${EXPORT_CERT_CHAIN_PATH}" || $(readlink "${EXPORT_CERT_CHAIN_PATH}") != "${CERTS}/${target}/${tld}-chain.pem" ]]; then
            update_link=1
        fi

        if [[ $update_link -eq 1 ]] && [[ $custom_cert -eq 0 ]]; then
            if ! diff -q "${CERTS}/${target}/${tld}-chain.pem" "${EXPORT_CERT_CHAIN_PATH}"; then  # update link only if different
                rm -f "${EXPORT_CERT_CHAIN_PATH}"
                ln -s "${CERTS}/${target}/${tld}-chain.pem" "${EXPORT_CERT_CHAIN_PATH}"
            fi
        else
            get_cert_subject "${EXPORT_CERT_CHAIN_PATH}"
        fi

    elif [[ -s "${CERTS}/${target}/${tld}-chain.pem" ]]; then  # no existing chain, create a new link
        ln -s "${CERTS}/${target}/${tld}-chain.pem" "${EXPORT_CERT_CHAIN_PATH}"
    else
        echo "${target} chain not found"  # shouldn't end up here (ever)
    fi
}

function assemble_private_cert_chain {
    local tld
    tld="${1}"
    [[ -n "${tld}" ]] || return

    # file exists and has a size of more than 0 bytes
    if [[ -s "${CERTS}/private/${tld}-chain.pem" ]]; then
        check_cert_expiry "${CERTS}/private/${tld}-chain.pem"
        expiring=$?
    fi

    # file doesn't exist or empty, or expiring soon
    if ! [[ -s "${CERTS}/private/${tld}-chain.pem" ]] || [[ $expiring -gt 0 ]]; then
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
        if [[ ! -L "${CERTS}/${cert}.pem" || $(readlink "${CERTS}/${cert}.pem") != "${CERTS}/private/${cert}.${tld}.pem" ]] \
          && [[ -s "${CERTS}/private/${cert}.${tld}.pem" ]]; then
            rm -f "${CERTS}/${cert}.pem"
            ln -s "${CERTS}/private/${cert}.${tld}.pem" "${CERTS}/${cert}.pem"
        fi
    done
}

function resolve_sans {
    # https://stackoverflow.com/a/11456496/1559300
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
    local sans
    # shellcheck disable=SC2048
    sans="$(for san in ${arr[*]}; do echo "-d ${san}.${tld} -d ${san}.${dns_tld}"; done)"
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
    # shellcheck disable=SC2048
    hosts="$(for san in ${arr[*]}; do printf '%s.%s\n%s.%s\n' "${san}" "${tld}" "${san}" "${dns_tld}"; done | tr '\n' ',')"
    echo "${hosts}"
    set +f
}

function get_server_ca {
    local tld
    tld="${1}"
    [[ -n "${tld}" ]] || return

    # shellcheck disable=SC2153
    if ! [[ -s "${CERTS}/private/server-ca.${tld}.pem" ]]; then
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
    if ! [[ -s "${CERTS}/private/root-ca.${tld}.pem" ]]; then
        curl --retry "${attempts}" --fail "${ca_http_url}/api/v1/cfssl/bundle" \
          --data "{\"certificate\": \"$(cat < "${CERTS}/private/server-ca.${tld}.pem" | awk '{printf "%s\\n", $0}')\"}" \
          | jq -r '.result.root' > "${CERTS}/private/root-ca.${tld}.pem"
    fi
}

function assemble_ca_bundle {
    if ! [[ -e "${CERTS}/ca-bundle.pem" ]] \
      && [[ -L "${CERTS}/server-ca.pem" ]] \
      && [[ -L "${CERTS}/root-ca.pem" ]]; then
        cat "${CERTS}/server-ca.pem" "${CERTS}/root-ca.pem" > "${CERTS}/ca-bundle.pem"
    fi
}

function check_cert_expiry() {
    [[ -e $1 ]] || return 1

    expiry_check="$(openssl x509 -noout \
      -checkend "${cert_seconds_until_expiry}" \
      -in "$1")"

    echo "$1 ${expiry_check} in $(( cert_seconds_until_expiry / 60 / 60 / 24 )) days"
    printf '\t%s\n\t%s\n' "$(get_cert_subject "$1")" "$(get_cert_issuer "$1")"

    if ! [[ "${expiry_check}" =~ 'will not expire' ]]; then
        return 1
    fi
}
export -f check_cert_expiry

function get_cert_issuer() {
    [[ -e $1 ]] || return 1
    local cert
    cert=$1

    cat <${cert} | openssl x509 -noout -issuer
}
export -f get_cert_issuer

function get_cert_subject() {
    [[ -e $1 ]] || return 1
    local cert
    cert=$1

    cat <${cert} | openssl x509 -noout -subject
}
export -f get_cert_subject

function check_self_signed_certs_expiry() {
    find "${CERTS}/private" -type f -name '*.pem' ! -name 'dhparam.*' \
      -exec /bin/bash -c 'check_cert_expiry "$0"' {} \;
}

function resolve_templates() {
    tmptmpl="$(mktemp)"
    if [[ -s $1 ]]; then
        cat < "$1" | envsubst > "${tmptmpl}"
    else
        echo '[]' > "${tmptmpl}"
    fi
    echo "${tmptmpl}"
}

function set_update_lock {
    if [[ -n $BALENA_SUPERVISOR_ADDRESS ]] && [[ -n $BALENA_SUPERVISOR_API_KEY ]]; then
        while [[ $(curl --silent --retry "${attempts}" --fail \
          "${BALENA_SUPERVISOR_ADDRESS}/v1/device?apikey=${BALENA_SUPERVISOR_API_KEY}" \
          -H "Content-Type: application/json" | jq -r '.update_pending') == 'true' ]]; do

            curl --silent --retry "${attempts}" --fail \
              "${BALENA_SUPERVISOR_ADDRESS}/v1/device?apikey=${BALENA_SUPERVISOR_API_KEY}" \
              -H "Content-Type: application/json" | jq -r

            sleep "$(( (RANDOM % 1) + 1 ))s"
        done
        sleep "$(( (RANDOM % 5) + 5 ))s"

        # https://www.balena.io/docs/learn/deploy/release-strategy/update-locking/
        lockfile /tmp/balena/updates.lock
    fi
}

function remove_update_lock() {
    rm -f /tmp/balena/updates.lock
}

rm -f "${CERTS}/.ready"

mkdir -p "${CERTS}/public" "${CERTS}/private" "$(dirname "${EXPORT_CERT_CHAIN_PATH}")"

while ! curl -I --fail "${ca_http_url}"; do sleep "$((RANDOM%10+1))s"; done

get_server_ca "${TLD}"
get_root_ca "${TLD}"

hosts="$(resolve_hosts "${DNS_TLD}" "${TLD}" "${SUBJECT_ALTERNATE_NAMES}")"
hosts="$(jq -c -n --arg hosts "${hosts::-1}" '$hosts | split(",")')"
sans="$(resolve_sans "${DNS_TLD}" "${TLD}" "${SUBJECT_ALTERNATE_NAMES}")"

# enter critical section
set_update_lock

# generate cryptographic assets
issue_private_certs "$(resolve_templates /opt/certs.json)"
issue_private_keys "$(resolve_templates /opt/keys.json)"
issue_public_certs "${BALENA_DEVICE_UUID}" "${DNS_TLD}" "${TLD}"
surface_root_certs "${TLD}"
assemble_ca_bundle
generate_compute_all "${TLD}"
assemble_private_cert_chain "${TLD}"
surface_resolved_cert_chain "${TLD}"

# signal healthy
touch "${CERTS}/.ready"

# remove lock
remove_update_lock

while true; do
    check_cert_expiry "${EXPORT_CERT_CHAIN_PATH}"
    check_self_signed_certs_expiry
    sleep 1d
done
