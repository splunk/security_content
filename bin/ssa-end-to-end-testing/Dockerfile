FROM docker.repo.splunkdev.net/ci-cd/ci-container:python-3.7-buster

RUN apt-get update
RUN apt-get install -y python3-dev git python-dev unzip python3-pip
RUN apt-get install -y python-gitdb

WORKDIR /app
RUN pip3 install -r requirements.txt

ENTRYPOINT ["python3", "detection_service.py"]
CMD ["-tfn", "T1003_002"]
