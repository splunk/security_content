FROM ubuntu:18.04

RUN apt-get update
RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata
RUN apt-get install -y python3-dev git python-dev unzip python3-pip awscli
RUN apt-get install -y python-gitdb
RUN apt-get install -y wget unzip

RUN wget --quiet https://releases.hashicorp.com/terraform/0.13.1/terraform_0.13.1_linux_amd64.zip \
  && unzip terraform_0.13.1_linux_amd64.zip \
  && mv terraform /usr/bin \
  && rm terraform_0.13.1_linux_amd64.zip

ADD . /app

WORKDIR /app
RUN pip3 install -r requirements.txt

ENTRYPOINT ["python3", "honeypot_service.py"]
CMD ["-a", "build", "-r", "eu-west-2", "-n", "songoku"]