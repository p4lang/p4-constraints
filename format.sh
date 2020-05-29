#!/bin/bash
# Formats source files according to Google's style guide. Requires clang-tidy.

# Only files with these extensions will be formatted.
EXTENSIONS="cc|h|proto"

find . -not -path ".third_party/**" \
  | egrep "\.(${EXTENSIONS})\$" \
  | xargs clang-format -style=google -i
