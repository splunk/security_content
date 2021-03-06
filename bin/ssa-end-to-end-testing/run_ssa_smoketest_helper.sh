#!/bin/bash

export VAULT_TOKEN=`cat /vault/.vault-token`

SCLOUD_TOKEN=$(vault read  -format json $SMOKETEST_VAULT_READ_PATH tenant=$TENANT | jq -r '.data.token')

virtualenv -p python3 smoketest && source smoketest/bin/activate && pip3 install -r requirements.txt

python run_ssa_smoketest.py -t $SCLOUD_TOKEN -e $DSP_ENV -s $TENANT -b $SRCBRANCH
