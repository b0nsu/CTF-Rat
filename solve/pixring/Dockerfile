FROM ubuntu:24.04@sha256:72297848456d5d37d1262630108ab308d3e9ec7ed1c3286a32fe09856619a782

ENV DEBIAN_FRONTEND=noninteractive
ENV PROB_NAME=pixring
ENV PORT=31340

RUN apt-get update && apt-get install -y --no-install-recommends \
    libjpeg-turbo8 \
    libpng16-16 \
    xinetd \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash ctf
WORKDIR /home/ctf

COPY ./deploy/${PROB_NAME} /home/ctf/${PROB_NAME}
COPY ./deploy/flag /home/ctf/flag
RUN mkdir -p /home/ctf/lib
COPY ./deploy/libc.so.6 /home/ctf/lib/libc.so.6
COPY ./deploy/ld-linux-x86-64.so.2 /home/ctf/lib/ld-linux-x86-64.so.2
COPY ./ctf.xinetd /etc/xinetd.d/ctf
COPY ./xinetd.conf /etc/xinetd.conf
RUN chmod 0644 /etc/xinetd.d/ctf /etc/xinetd.conf

RUN chown -R root:ctf /home/ctf
RUN chmod 0750 /home/ctf
RUN chown root:root /home/ctf/${PROB_NAME} /home/ctf/flag
RUN chown -R root:root /home/ctf/lib
RUN chmod 0755 /home/ctf/${PROB_NAME}
RUN chmod 0755 /home/ctf/lib /home/ctf/lib/ld-linux-x86-64.so.2
RUN chmod 0644 /home/ctf/lib/libc.so.6
RUN chmod 0444 /home/ctf/flag

EXPOSE ${PORT}

CMD ["/usr/sbin/xinetd", "-dontfork"]
