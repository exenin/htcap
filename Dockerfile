FROM kalilinux/kali-linux-docker
# Metadata params
ARG BUILD_DATE
ARG VERSION
ARG VCS_URL
ARG VCS_REF

RUN echo "deb http://http.kali.org/kali kali-rolling main contrib non-free" > /etc/apt/sources.list && \
echo "deb-src http://http.kali.org/kali kali-rolling main contrib non-free" >> /etc/apt/sources.list

ENV DEBIAN_FRONTEND noninteractive
RUN set -x \
&& apt-get -yqq update \
&& apt-get -yqq dist-upgrade \
&& apt-get clean

# HTCAP STUFF
RUN apt-get -yqq install npm wapiti sqlmap arachni curl

COPY src /var/app

WORKDIR /var/app/WORKSPACE

RUN cd /var/app && npm install

COPY etc/entry.sh /var/app/WORKSPACE/entry.sh

VOLUME /src/WORKSPACE/DATAVOL /var/app/DATAVOL

ENTRYPOINT bash entry.sh
