docker build -t tiny_hard_user .
docker rm -f tiny_hard
docker run --privileged -d -p 9041:9041 --name tiny_hard tiny_hard_user
