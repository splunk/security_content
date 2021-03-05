#!/bin/bash

qbec --yes apply $SCSENV --vm:ext-str SRCBRANCH --vm:ext-str CI_COMMIT_SHORT_SHA -c service-account -c smoketest --wait-timeout "1m"
