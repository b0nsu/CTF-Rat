FROM ubuntu:22.04@sha256:340d9b015b194dc6e2a13938944e0d016e57b9679963fdeb9ce021daac430221

RUN apt update
RUN apt-get install -y socat adduser

RUN adduser -u 1337 pwn

WORKDIR /home/pwn

COPY ./flag ./flag
COPY ./deploy/prob ./prob

RUN chmod 644 ./flag
RUN chmod 755 ./prob

USER pwn

EXPOSE 8080
CMD socat TCP-LISTEN:8080,reuseaddr,fork EXEC:./prob,stderr