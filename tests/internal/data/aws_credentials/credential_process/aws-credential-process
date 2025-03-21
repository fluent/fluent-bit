#!/bin/sh

printf '{"Version":1,"AccessKeyId":"%s","SecretAccessKey":"%s"' "${1}" "${_AWS_SECRET_ACCESS_KEY}"
if [ -n "${_AWS_SESSION_TOKEN}" ]; then
    printf ',"SessionToken":"%s"' "${_AWS_SESSION_TOKEN}"
fi
if [ -n "${_AWS_EXPIRATION}" ]; then
    printf ',"Expiration":"%s"' "$(/bin/date -d "${_AWS_EXPIRATION}" --utc '+%Y-%m-%dT%H:%M:%SZ')"
fi
printf '}'

if [ -n "${_AWS_EXIT_CODE}" ]; then
    exit "${_AWS_EXIT_CODE}"
fi
