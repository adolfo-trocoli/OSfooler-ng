# Use an official Python runtime as a parent image
FROM ubuntu:24.04

#____STARTS_HERE 

ARG REPO=https://github.com/staticgears/OSfooler-ng.git
ARG CHECKOUT=/build
ARG SERVICE=osfooler_ng.service
ARG OS_NAME="Microsoft Windows 2000 SP4"
ARG OSGENRE=Windows
ARG DETAILS_P0F="2000 SP4"

# Set (temporarily) DEBIAN_FRONTEND to avoid interacting with tzdata
RUN apt-get -qq -y update && \
    DEBIAN_FRONTEND=noninteractive apt-get -qq -y install \
        python3 \
        python3-dev \
        python3-venv \
        git \
        build-essential \
        libnetfilter-queue-dev \
        iptables

WORKDIR ${CHECKOUT}
ARG CACHEBUST=1
#checkout service and populate it
RUN git clone ${REPO}

RUN python3 -m venv bubble && \
    . bubble/bin/activate && \
    python3 -m pip install -r ${CHECKOUT}/OSfooler-ng/requirements.txt

WORKDIR ${CHECKOUT}/OSfooler-ng/service
RUN sed -i -e "s/__OS_NAME/${OS_NAME}/" \
        -e "s/__OSGENRE/${OSGENRE}/" \
        -e "s/__DETAILS_P0F/${DETAILS_P0F}/" \
        wrapper.sh

RUN chown root:root start.sh stop.sh && \
    chmod 4500 start.sh stop.sh

RUN DEBIAN_FRONTEND=noninteractive apt-get -qq -y autoclean && \
    DEBIAN_FRONTEND=noninteractive apt-get -qq -y autoremove && \
    rm -rf /var/lib/apt/lists/*

#__ENDS_HERE

# Use C.UTF-8 locale to avoid issues with ASCII encoding
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
        
WORKDIR /home/docker/data
ENV HOME /home/docker
ENV USER docker
USER docker 
ENV PATH /home/docker/.local/bin:$PATH
# Avoid first use of sudo warning. c.f. https://askubuntu.com/a/22614/781671
#RUN touch $HOME/.sudo_as_admin_successful
        
#CMD [ "${CHECKOUT}/OSfooler-ng/service/start.sh" ]
CMD [ "/bin/bash" ]
