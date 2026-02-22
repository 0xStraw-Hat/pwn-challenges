FROM debian:stable-slim

RUN apt-get update && \
    useradd -m ctf && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /home/ctf

COPY chall .
COPY flag.txt .
COPY run.sh .
COPY ynetd .
COPY libc.so.6 .
COPY ld-linux-x86-64.so.2 .

RUN chmod 755 chall ynetd run.sh ld-linux-x86-64.so.2 libc.so.6
RUN chmod 444 flag.txt

EXPOSE 9999

CMD ["./run.sh"]
