#!/bin/bash
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

#
# Formats source files according to Google's style guide. Requires clang-format.
# 
# If you're on macOS with Apple silicon (M1, M2, M3, ...), call using
# ```
# PLATFORM=darown-arm64 ./format.sh
# ```
# 
# If you're on macOS with Intel silicon, call using
# ```
# PLATFORM=darown-amd64 ./format.sh
# ```
# and similarly for other platforms.

# Possible values: {linux, darwin}_{amd64, arm64}.
which dpkg
exit_status=$?
if [ ${exit_status} -eq 0 ]
then
    ARCH=`dpkg --print-architecture`
    PLATFORM=${PLATFORM:-linux-${ARCH}}
else
    # Guess amd64
    PLATFORM=${PLATFORM:-linux-amd64}
fi

# Only files with these extensions will be formatted by clang-format.
CLANG_FORMAT_EXTENSIONS="cc|h|proto"

# Run clang-format.
find . -not -path "./third_party/**" \
  | egrep "\.(${CLANG_FORMAT_EXTENSIONS})\$" \
  | xargs clang-format --verbose -style=google -i

# Run buildifier (Bazel file formatter).
if [ ! -e buildifier ]
then
    BUILDIFIER="buildifier-$PLATFORM"
    wget "https://github.com/bazelbuild/buildtools/releases/download/v8.0.3/$BUILDIFIER"
    mv $BUILDIFIER buildifier
    chmod +x buildifier
fi
./buildifier --lint=fix -r .
