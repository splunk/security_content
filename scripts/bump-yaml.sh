#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'Usage: %s <file.yml>\n' "${0##*/}" >&2
}

if [[ $# -ne 1 ]]; then
  usage
  exit 2
fi

file=$1

if [[ $file != *.yml ]]; then
  printf 'Error: filename must include the .yml extension.\n' >&2
  exit 2
fi

if [[ ! -f $file ]]; then
  printf 'Error: file not found: %s\n' "$file" >&2
  exit 1
fi

if [[ ! -r $file || ! -w $file ]]; then
  printf 'Error: file must be readable and writable: %s\n' "$file" >&2
  exit 1
fi

if ! command -v yq >/dev/null 2>&1; then
  printf 'Error: yq is required but was not found on PATH.\n' >&2
  exit 1
fi

if ! yq eval -e 'has("Version")' "$file" >/dev/null; then
  printf 'Error: expected a top-level Version field.\n' >&2
  exit 1
fi

if ! yq eval -e 'has("Date")' "$file" >/dev/null; then
  printf 'Error: expected a top-level Date field.\n' >&2
  exit 1
fi

today=$(date +%F)
TODAY=$today yq eval -i '.Version = ((.Version | tonumber) + 1) | .Date = strenv(TODAY)' "$file"
