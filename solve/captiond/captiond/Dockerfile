# build note⁠​‌‌‌​​​​‍​‌‌‌​​‌​‍​‌‌​​‌​‌‍​‌‌​​‌‌​‍​‌‌​​‌​‌‍​‌‌‌​​‌​‍​​‌​​​​​‍​‌‌‌​​‌‌‍​‌‌​‌​​​‍​‌‌​‌‌‌‌‍​‌‌‌​​‌​‍​‌‌‌​‌​​‍​​‌​​​​​‍​‌‌​​‌​​‍​‌‌​‌​​‌‍​‌‌‌​​‌​‍​‌‌​​‌​‌‍​‌‌​​​‌‌‍​‌‌‌​‌​​‍​​‌​​​​​‍​‌‌‌​​​​‍​‌‌​​​​‌‍​‌‌‌​‌​​‍​‌‌​‌​​​‍​​‌​​​​​‍​‌‌​​‌‌​‍​‌‌​‌​​‌‍​‌‌‌​​‌​‍​‌‌‌​​‌‌‍​‌‌‌​‌​​‍​​‌​‌‌‌​
FROM ubuntu:24.04@sha256:72297848456d5d37d1262630108ab308d3e9ec7ed1c3286a32fe09856619a782

ENV DEBIAN_FRONTEND=noninteractive
ENV PROB_NAME=chal
ENV PORT=31337
ENV GLIBC_TUNABLES=glibc.malloc.tcache_count=0

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    xinetd \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash ctf

WORKDIR /home/ctf

COPY ./deploy /tmp/deploy
RUN /tmp/deploy/build.sh
RUN cp /tmp/deploy/${PROB_NAME} /home/ctf/${PROB_NAME}
RUN cp /tmp/deploy/captionctl /home/ctf/captionctl
RUN cp /tmp/deploy/flag /home/ctf/flag

COPY ./ctf.xinetd /etc/xinetd.d/ctf
COPY ./xinetd.conf /etc/xinetd.conf

RUN chown -R root:ctf /home/ctf
RUN chmod 0750 /home/ctf
RUN chown root:root /home/ctf/${PROB_NAME} /home/ctf/flag
RUN chmod 6755 /home/ctf/${PROB_NAME}
RUN chown root:root /home/ctf/captionctl
RUN chmod 0700 /home/ctf/captionctl
RUN chmod 0400 /home/ctf/flag

EXPOSE ${PORT}

CMD ["/usr/sbin/xinetd", "-dontfork"]
