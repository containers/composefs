FROM fedora:latest

RUN dnf install -y git make clang-tools-extra

WORKDIR /src

COPY run-tests.sh /usr/local/bin
ENTRYPOINT /usr/local/bin/run-tests.sh
