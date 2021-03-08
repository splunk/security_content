FROM docker.repo.splunkdev.net/ci-cd/ci-container:debian-buster

ARG SRCBRANCH=develop
ARG SCSENV=app_play1

ARG KUBECTL_VERSION=v1.10.9

ENV QBEC_VERSION 0.12.1
ENV QBEC_SHA 6fbec2c33ff15c603585a22c100aa839461680cf775a1f90336078bf79c6a42f

ENV SRCBRANCH=${SRCBRANCH}
ENV SCSENV=${SCSENV}

RUN mkdir /deployer && \
    apt-get update && \
    apt-get install -y bash tar curl && \
    # Install kubetctl
    curl -L https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl -o /usr/local/bin/kubectl && \
    chmod +x /usr/local/bin/kubectl && \
    # Install qbec
    curl -L -O https://github.com/splunk/qbec/releases/download/v${QBEC_VERSION}/qbec-linux-amd64.tar.gz && \
    echo "${QBEC_SHA}  qbec-linux-amd64.tar.gz" | sha256sum -c && \
    tar -xzf qbec-linux-amd64.tar.gz -C /usr/local/bin qbec && rm -rf qbec-linux-amd64.tar.gz

COPY k8s /deployer/k8s

RUN chmod +x /deployer/k8s/deployer.sh

WORKDIR /deployer/k8s