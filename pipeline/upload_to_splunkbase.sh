#!/bin/bash

# Check if all required variables are set

FILE_PATH="/builds/threat-research/security_content/artifacts/DA-ESS-ContentUpdate-latest.tar.gz"
FILE_NAME="DA-ESS-ContentUpdate-latest.tar.gz" 
SPLUNKBASE_USERNAME=$SPLUNKBASE_USERNAME
SPLUNKBASE_PASSWORD=$SPLUNKBASE_PASSWORD

if [ -z "$FILE_PATH" ] || [ -z "$FILE_NAME" ] || [ -z "$SPLUNKBASE_USERNAME" ] || [ -z "$SPLUNKBASE_PASSWORD" ]; then
  echo "One or more required variables are undefined."
  exit 1
fi

curl -u "${SPLUNKBASE_USERNAME}:${SPLUNKBASE_PASSWORD}" --request POST https://splunkbase.splunk.com/api/v1/app/3449/new_release/ \
     -F "files[]=@${FILE_PATH}" \
     -F "filename=${FILE_NAME}" \
     -F "cim_versions=5.x,4.x" \
     -F "splunk_versions=9.2,9.1,9.0,8.2,8.1,8.0,7.3" \
     -F "visibility=false" \
     -o /dev/null -s -w "%{http_code}"
