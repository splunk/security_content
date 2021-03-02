#!/bin/bash

qbec --yes apply $SCSENV --vm:ext-str SCBRANCH=$SRCBRANCH -c smoketest --wait-timeout "1m"