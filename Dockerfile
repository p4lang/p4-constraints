FROM ubuntu:16.04

ARG DEBIAN_FRONTEND=noninteractive

COPY . /p4-constraints/
WORKDIR /p4-constraints/

RUN apt-get update
RUN apt-get install -y --no-install-recommends \
  wget \
  ca-certificates \
  build-essential \
  git \
  python3 \
  libgmp-dev \
  bison \
  flex \
  libfl-dev

RUN update-ca-certificates

RUN wget "https://github.com/bazelbuild/bazelisk/releases/download/v1.4.0/bazelisk-linux-amd64"
RUN chmod +x bazelisk-linux-amd64
RUN ln -s $(pwd)/bazelisk-linux-amd64 /usr/local/bin/bazel
