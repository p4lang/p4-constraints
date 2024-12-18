#!/bin/bash
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
PLATFORM=${PLATFORM:-linux-amd64}

# Only files with these extensions will be formatted by clang-format.
CLANG_FORMAT_EXTENSIONS="cc|h|proto"

# Run clang-format.
find . -not -path "./third_party/**" \
  | egrep "\.(${CLANG_FORMAT_EXTENSIONS})\$" \
  | xargs clang-format --verbose -style=google -i

# Run buildifier (Bazel file formatter).
BUILDIFIER="buildifier-$PLATFORM"
wget "https://github.com/bazelbuild/buildtools/releases/download/v7.3.1/$BUILDIFIER"
mv $BUILDIFIER buildifier
chmod +x buildifier
./buildifier --lint=fix -r .
