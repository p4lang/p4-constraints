# Copyright 2020 The P4-Constraints Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

FROM ubuntu:24.04

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
