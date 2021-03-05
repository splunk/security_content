#!/bin/bash

export VAULT_TOKEN=`cat /vault/.vault-token`

SCLOUD_TOKEN=$(vault read  -format json $SMOKETEST_VAULT_READ_PATH --tenant=$TENANT | jq -r '.data.token')

git clone https://github.com/splunk/security_content.git && cd security_content && git checkout $SRCBRANCH

cd bin/ssa-end-to-end-testing

virtualenv -p python3 smoketest && source smoketest/bin/activate && pip3 install -r requirements.txt

python run_ssa_smoketest.py -t $SCLOUD_TOKEN -e $DSP_ENV -s $TENANT