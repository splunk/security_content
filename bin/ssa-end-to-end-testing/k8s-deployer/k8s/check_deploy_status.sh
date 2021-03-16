#!/bin/bash

set -o pipefail
set -o nounset

set -o errexit
#This script is used to check the status of the smoketest k8s job: the tests pass if {.status.succeeded} returns 1.
# Then retrieve the job logs once it's completed.
smoketest_k8s_job=$(kubectl get jobs -o json | jq -r --arg COMMIT "${CI_COMMIT_SHORT_SHA}" '.items[] | select(.kind=="Job") | select(.metadata.labels.uploaderLabel==$COMMIT) | .metadata.name')
echo >&2 "Create smoketest k8s job: $smoketest_k8s_job"
smoketest_k8s_pod=$(kubectl get pods -o custom-columns=:metadata.name | grep ${smoketest_k8s_job})
echo >&2 "Create smoketest k8s pod: $smoketest_k8s_pod"
echo >&2 "Checking if smoketest starts running..."
set +o errexit

#Wait for job ready to run as background process, returns 1 if smoketest job still in Pod Initializing stage.
#Will exit if the pod is not up after 5 minutes(max_retries = 30)
job_running=1
counter=1
MAX_RETRIES=30

while [[ $job_running -ne 0 ]] && [[ $counter -le $MAX_RETRIES ]]; do
    kubectl wait --for=condition=ready pod/${smoketest_k8s_pod} --timeout=10s
    job_running=$?
    echo >&2 "Checking if smoketest job starts running (return 0 if the job is ready to run):" $job_running
    ((counter++))
    if [[ $counter -eq $MAX_RETRIES ]]; then
        kubectl get pods
        echo "Smoke test pod is not up after 5 minutes. Will exit."
        exit 1
    fi
done

set -o errexit
kubectl logs -f ${smoketest_k8s_pod}
echo >&2 "Complete retrieving smoketest job logs."


#Add more loggings to capture more info for k8s error that happens sporadically
set +o errexit
echo >&2 "Printing command: kubectl get job/${smoketest_k8s_job}"
echo >&2 "$(kubectl get job/${smoketest_k8s_job})"
echo >&2 "$(kubectl get job/${smoketest_k8s_job} -o jsonpath='{.status}')"

echo >&2 "Printing command with extra space: kubectl get job/${smoketest_k8s_job} "
echo >&2 "$(kubectl get job/${smoketest_k8s_job} )"
echo >&2 "$(kubectl get job/${smoketest_k8s_job}  -o jsonpath='{.status}')"

echo >&2 "Printing command kubectl get jobs ${smoketest_k8s_job} -o jsonpath='{.status}'"
echo >&2 "$(kubectl get jobs ${smoketest_k8s_job} -o jsonpath='{.status}')"
echo >&2 "*****End of logging for k8s error debugging *****"
set -o errexit


SUCCESS=$(kubectl get job/${smoketest_k8s_job} -o jsonpath='{.status.succeeded}')
if [[ $SUCCESS -ne 1 ]]; then
    echo "Smoke test failed. Please refer to the test logs."
    exit 1
fi
echo "All smoke tests passed!"