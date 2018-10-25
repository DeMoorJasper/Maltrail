FROM debian:jessie

RUN apt-get update && apt-get upgrade -y && apt-get install -y python-pcapy
RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && python get-pip.py && pip install impacket
RUN git clone https://github.com/stamparm/maltrail.git /root/maltrail && python /root/maltrail/core/update.py

WORKDIR /root/maltrail

COPY run.sh /root/run.sh

ENTRYPOINT  ["/bin/bash", "/root/run.sh"]

