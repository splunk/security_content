FROM ubuntu:18.04

RUN apt-get update
RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata
RUN apt-get install -y python3-dev git python-dev unzip python3-pip awscli
RUN apt-get install -y python-gitdb
RUN apt-get install -y wget unzip
RUN apt-get install -y git

ADD . /app

WORKDIR /app
RUN pip3 install -r requirements.txt

ENTRYPOINT ["python3", "detection_testing_execution.py"]
CMD ["-b", "automated_detections_testing_2"]
