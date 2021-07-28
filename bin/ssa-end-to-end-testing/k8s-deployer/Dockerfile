FROM docker.repo.splunkdev.net/ci-cd/ci-container:debian-buster

ARG SRCBRANCH=develop
ARG SCSENV=app_play1

ENV KUBECTL_VERSION=v1.15.12

ENV QBEC_VERSION=v0.12.3

ENV SRCBRANCH=${SRCBRANCH}
ENV SCSENV=${SCSENV}

RUN mkdir /deployer && \
    apt-get update && \
    apt-get install -y bash tar curl

RUN curl -L https://storage.googleapis.com/kubernetes-release/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl -o /usr/local/bin/kubectl && chmod +x /usr/local/bin/kubectl
RUN curl -L https://github.com/splunk/qbec/releases/download/${QBEC_VERSION}/qbec-linux-amd64.tar.gz -o /root/qbec.tar.gz && tar -xvzf /root/qbec.tar.gz -C /usr/local/bin/

COPY k8s /deployer/k8s

RUN chmod +x /deployer/k8s/deployer.sh
RUN chmod +x /deployer/k8s/check_deploy_status.sh

WORKDIR /deployer/k8s
