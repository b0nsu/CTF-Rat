FROM ubuntu:26.04@sha256:b7f48194d4d8b763a478a621cdc81c27be222ba2206ca3ca6bc42b49685f3d9e

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       xinetd ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash ctf

WORKDIR /home/ctf
COPY chall flag ./
COPY xinetd.conf /etc/xinetd.conf
COPY ctf.xinetd /etc/xinetd.d/ctf

RUN chown -R root:root /home/ctf \
    && chmod 755 /home/ctf \
    && chmod 755 /home/ctf/chall \
    && chmod 444 /home/ctf/flag

EXPOSE 31337
CMD ["/usr/sbin/xinetd", "-dontfork"]
