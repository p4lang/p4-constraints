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

# Formats source files according to Google's style guide. Requires clang-format.

# Only files with these extensions will be formatted by clang-format.
CLANG_FORMAT_EXTENSIONS="cc|h|proto"

# Run clang-format.
find . -not -path "./third_party/**" \
| egrep "\.(${CLANG_FORMAT_EXTENSIONS})\$" \
| xargs clang-format --verbose -style=google -i

bazel run -- \
@buildifier_prebuilt//:buildifier --lint=fix -r $(bazel info workspace)

# =============================================================================
# Format Markdown files according to Google's Markdown Style Guide.
# https://google.github.io/styleguide/docguide/style.html
# =============================================================================

format_markdown_file() {
    local file="$1"
    local tmp_file
    tmp_file=$(mktemp)

    echo "Formatting Markdown: $file"

    cp "$file" "$tmp_file"

    # -------------------------------------------------------------------------
    # 1. TRAILING WHITESPACE
    # Remove trailing spaces/tabs from each line.
    # -------------------------------------------------------------------------
    sed -i 's/[[:space:]]*$//' "$tmp_file"

    # -------------------------------------------------------------------------
    # 2. ATX-STYLE HEADINGS
    # Convert setext-style headings to ATX style.
    # e.g. "Heading\n=======" -> "# Heading"
    # e.g. "Heading\n-------" -> "## Heading"
    # -------------------------------------------------------------------------
    awk '
    NR > 1 {
        prev_line = curr_line
        curr_line = $0
        if (curr_line ~ /^=+[[:space:]]*$/ && prev_line != "") {
            print "# " prev_line
            curr_line = ""
            prev_printed = 1
            next
        } else if (curr_line ~ /^-+[[:space:]]*$/ && prev_line != "") {
            print "## " prev_line
            curr_line = ""
            prev_printed = 1
            next
        } else {
            if (!prev_printed) print prev_line
            prev_printed = 0
        }
        next
    }
    NR == 1 { curr_line = $0; prev_printed = 0 }
    END { if (!prev_printed) print curr_line }
    ' "$tmp_file" > "${tmp_file}.awk" && mv "${tmp_file}.awk" "$tmp_file"

    # -------------------------------------------------------------------------
    # 3. ADD SPACING TO HEADINGS
    # Ensure a space exists after # in headings.
    # e.g. "##Heading" -> "## Heading"
    # -------------------------------------------------------------------------
    sed -i 's/^\(#\+\)\([^[:space:]#]\)/\1 \2/' "$tmp_file"

    # -------------------------------------------------------------------------
    # 4. BLANK LINE BEFORE HEADINGS
    # Ensure there is a blank line before every heading.
    # -------------------------------------------------------------------------
    awk '
    /^#{1,6} / {
        if (NR > 1 && prev != "") print ""
    }
    { print; prev = $0 }
    ' "$tmp_file" > "${tmp_file}.awk" && mv "${tmp_file}.awk" "$tmp_file"

    # -------------------------------------------------------------------------
    # 5. BLANK LINE AFTER HEADINGS
    # Ensure there is a blank line after every heading.
    # -------------------------------------------------------------------------
    awk '
    /^#{1,6} / {
        print
        getline next_line
        if (next_line != "") print ""
        print next_line
        next
    }
    { print }
    ' "$tmp_file" > "${tmp_file}.awk" && mv "${tmp_file}.awk" "$tmp_file"

    # -------------------------------------------------------------------------
    # 6. FENCED CODE BLOCKS
    # Convert top-level indented code blocks (4 spaces) to fenced code blocks.
    # -------------------------------------------------------------------------
    awk '
    BEGIN { in_code = 0; in_list = 0 }
    /^[*\-] / || /^[0-9]+\. / { in_list = 1 }
    /^$/ { in_list = 0 }
    !in_list && /^    [^ ]/ && !in_code {
        print "```"
        sub(/^    /, "")
        print
        in_code = 1
        next
    }
    in_code && /^    / {
        sub(/^    /, "")
        print
        next
    }
    in_code && !/^    / {
        print "```"
        in_code = 0
        print
        next
    }
    { print }
    END { if (in_code) print "```" }
    ' "$tmp_file" > "${tmp_file}.awk" && mv "${tmp_file}.awk" "$tmp_file"

    # -------------------------------------------------------------------------
    # 7. MULTIPLE BLANK LINES
    # Collapse multiple consecutive blank lines into a single blank line.
    # -------------------------------------------------------------------------
    cat -s "$tmp_file" > "${tmp_file}.squeeze" && mv "${tmp_file}.squeeze" "$tmp_file"

    # -------------------------------------------------------------------------
    # 8. SINGLE NEWLINE AT END OF FILE
    # -------------------------------------------------------------------------
    awk 'BEGIN{RS=""; ORS="\n\n"} {gsub(/\n+$/, ""); print}' "$tmp_file" | \
        head -c -1 > "${tmp_file}.eof"
    printf '\n' >> "${tmp_file}.eof"
    mv "${tmp_file}.eof" "$tmp_file"

    # -------------------------------------------------------------------------
    # 9. LINE LENGTH WARNING (80 chars)
    # Warn about lines exceeding 80 characters, excluding links, tables,
    # headings, and code blocks as per the style guide.
    # -------------------------------------------------------------------------
    local line_num=0
    local in_code_block=0
    while IFS= read -r line; do
        line_num=$((line_num + 1))
        if [[ "$line" =~ ^\`\`\` ]]; then
            if [ $in_code_block -eq 0 ]; then
                in_code_block=1
            else
                in_code_block=0
            fi
        fi
        if [ $in_code_block -eq 0 ]; then
            if [[ ! "$line" =~ ^\# ]] && \
               [[ ! "$line" =~ \| ]] && \
               [[ ! "$line" =~ \]\( ]] && \
               [[ ! "$line" =~ \]\: ]]; then
                if [ ${#line} -gt 80 ]; then
                    echo "  WARNING: $file:$line_num exceeds 80 chars (${#line} chars)"
                fi
            fi
        fi
    done < "$tmp_file"

    mv "$tmp_file" "$file"
}

# Find and format all Markdown files, excluding third_party.
echo "Formatting Markdown files..."
find . -not -path "./third_party/**" -name "*.md" -type f | while read -r file; do
    format_markdown_file "$file"
done
echo "Markdown formatting complete."