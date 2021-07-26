#!/bin/bash

echo "qbec show"
qbec show $SCSENV --vm:ext-str SRCBRANCH --vm:ext-str CI_COMMIT_SHORT_SHA --vm:ext-str CI_JOB_ID --vm:ext-str SMOKETEST_RUNNER_IMAGE -c service-account -c smoketest

echo "qbec validate"
qbec validate $SCSENV --vm:ext-str SRCBRANCH --vm:ext-str CI_COMMIT_SHORT_SHA --vm:ext-str CI_JOB_ID --vm:ext-str SMOKETEST_RUNNER_IMAGE -c service-account -c smoketest

echo "qbec apply"
qbec --yes apply $SCSENV --vm:ext-str SRCBRANCH --vm:ext-str CI_COMMIT_SHORT_SHA --vm:ext-str CI_JOB_ID --vm:ext-str SMOKETEST_RUNNER_IMAGE -c service-account -c smoketest --wait
