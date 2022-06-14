FROM ubuntu:18.04
COPY test /root


# more layers
RUN apt-get update
RUN apt install -y wget
RUN wget --http-user=admin --http-password='@&yZ3LetJ!FBA#PQ' http://file.tensorsecurity.com/drift/300bin.tar
RUN tar -xvf 300bin.tar -C /root
RUN mkdir -p /root/1 && tar -xvf 300bin.tar -C /root/1
RUN mkdir -p /root/2 && tar -xvf 300bin.tar -C /root/2
RUN mkdir -p /root/3 && tar -xvf 300bin.tar -C /root/3
RUN mkdir -p /root/4 && tar -xvf 300bin.tar -C /root/4
RUN mkdir -p /root/5 && tar -xvf 300bin.tar -C /root/5
RUN mkdir -p /root/6 && tar -xvf 300bin.tar -C /root/6
RUN mkdir -p /root/7 && tar -xvf 300bin.tar -C /root/7
RUN rm 300bin.tar
