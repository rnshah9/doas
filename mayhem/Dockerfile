FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential bison flex libpam0g-dev clang

COPY . /repo
WORKDIR /repo
ENV DESTDIR=/install
RUN make -j8
RUN make install
RUN clang++ /repo/mayhem/fuzz_copyenvpw.cpp /repo/env.o -fsanitize=fuzzer,address -o /fuzz

FROM ubuntu:20.04 as package
COPY --from=builder /repo/doas /
COPY --from=builder /fuzz /fuzz_copyenvpw
