FROM ubuntu:22.04@sha256:20fa2d7bb4de7723f542be5923b06c4d704370f0390e4ae9e1c833c8785644c1

RUN apt-get update && apt-get install -y python3 socat

RUN adduser pwn
WORKDIR /home/pwn

COPY ./deploy/libchal.so ./libchal.so
COPY ./deploy/chal.py ./chal.py
COPY ./flag ./flag

RUN chmod 755 ./flag ./libchal.so

USER pwn
EXPOSE 8080
CMD socat TCP-LISTEN:8080,reuseaddr,fork EXEC:"python3 chal.py"
