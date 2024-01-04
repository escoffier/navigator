FROM ubuntu:22.04

RUN sed -i 's/ports.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list

#RUN sed -i 's/archive.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list

RUN apt-get -y update \
  && apt-get -y install --no-install-recommends ca-certificates git ssh clang clangd cmake make tar libgflags-dev libgtest-dev wget libnghttp2-dev libfmt-dev libboost-dev 2>&1 \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*p

RUN wget https://github.com/nodejs/llhttp/archive/refs/tags/release/v9.0.1.tar.gz --no-check-certificate && tar -zxvf v9.0.1.tar.gz \
  && cd llhttp-release-v9.0.1 && mkdir build && cd build && cmake -DBUILD_STATIC_LIBS=ON .. && make && make install
#COPY v9.0.1.tar.gz .
RUN wget https://github.com/google/glog/archive/refs/tags/v0.6.0.tar.gz --no-check-certificate && tar -zxvf v0.6.0.tar.gz \
  && cd glog-0.6.0  && cmake -DBUILD_SHARED_LIBS=OFF -DWITH_CUSTOM_PREFIX=ON -S . -B build && cmake --build build --target install

RUN wget https://github.com/PCRE2Project/pcre2/archive/refs/tags/pcre2-10.42.tar.gz && tar -zxvf pcre2-10.42.tar.gz \
  && cd pcre2-pcre2-10.42 && cmake -S . -B build && cmake --build build --target install
# RUN tar -zxvf v9.0.1.tar.gz \
#     && cd llhttp-release-v9.0.1 && mkdir build && cd build && cmake -DBUILD_STATIC_LIBS=ON .. && make && make install