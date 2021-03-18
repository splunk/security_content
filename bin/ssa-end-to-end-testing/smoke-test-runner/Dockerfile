# Base image that support pod to communicate with SCS Vault to fetch IAC token as well to support python3 pytest framework
FROM docker.repo.splunkdev.net/ci-cd/ci-container:python-3.7-buster

ARG SRCBRANCH=develop

RUN mkdir smoketest && \
    /usr/local/bin/python -m pip install --upgrade pip && \
    pip install pytest && pip install requests && pip install virtualenv

RUN git clone https://github.com/splunk/security_content.git -b ${SRCBRANCH}

RUN chmod +x security_content/bin/ssa-end-to-end-testing/run_ssa_smoketest_helper.sh

RUN curl -L https://github.com/splunk/splunk-cloud-sdk-go/releases/download/v1.11.1/scloud_v7.1.0_linux_amd64.tar.gz | tar -xz -C /usr/bin 

COPY --from=docker.repo.splunkdev.net/kub/debug-tools:latest /usr/local/bin/vault /usr/local/bin/vault

WORKDIR /security_content/bin/ssa-end-to-end-testing
