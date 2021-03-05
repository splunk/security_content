# Base image that support pod to communicate with SCS Vault to fetch IAC token as well to support python3 pytest framework
FROM docker.repo.splunkdev.net/ci-cd/ci-container:python-3.7-buster

RUN mkdir smoketest && \
    /usr/local/bin/python -m pip install --upgrade pip && \
    pip install pytest && pip install requests && pip install virtualenv

#RUN mkdir smoketest && \
#    /usr/local/bin/python -m pip install --upgrade pip && \
#    pip install pytest && pip install requests && pip install virtualenv \
#    # Docker Engine Install
#    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - && \
#    apt-key fingerprint 0EBFCD88 && \
#    add-apt-repository \
#    "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
#    $(lsb_release -cs) \
#    stable" && \
#    apt-get install -y docker-ce docker-ce-cli containerd.io

COPY entrypoint.sh /smoketest/entrypoint.sh
RUN chmod +x /smoketest/*

RUN curl -L https://github.com/splunk/splunk-cloud-sdk-go/releases/download/v1.11.1/scloud_v7.1.0_linux_amd64.tar.gz | tar -xz -C /usr/bin 

COPY --from=docker.repo.splunkdev.net/kub/debug-tools:latest /usr/local/bin/vault /usr/local/bin/vault
