"""Bazel targets for end-to-end diff testing of p4_constraints library.

This file defines targets `run_p4check` and `diff_test`, which are intended to be
used in conjunction for "golden file testing" as follows:
```build
    run_p4check(
        name = "main_p4check",
        src = "main.p4",
        out = ["main.p4check.output"],
        table_entries = ["ipv4_table_entry_1.pb.txt, acl_table_entry_1.pb.txt"],
        deps = ["included_in_main.p4", "header.h"],  # allows for `#include`
    )

    diff_test(
        name = "main_test",
        actual = ":main_p4check",
        expected = "main.expected.output"  # golden file
    )
```
The run_p4check target proceeds as follows:
  1. It compiles the .p4 source file to a p4info.proto text file using p4c.
  2. It invokes p4check on the .p4info file, checking the given `table_entries`.
  3. It records the output of p4check to the given `out` file.

The diff_test target then computes the diff of the `actual` output and the
`expected` output, either succeeding if the diff is empty or failing and
printing the nonempty diff otherwise. To auto-generate or update the expected
file, run:
```sh
    bazel run <diff test target> -- --update`
```
"""

load("@com_github_p4lang_p4c//:bazel/p4_library.bzl", "p4_library")

def run_p4check(name, src, out, deps = [], table_entries = [], visibility = None):
    """Runs p4check on the given P4 file and table entries, recording output.

    The P4 `src` file is first compiled to p4info, and then passed to p4check
    together with the `table_entries` (if specified). The result is recorded
    in `out`.

    Args:
      name: Name of this target.
      src: P4 source file.
      deps: List of additional P4 dependencies (optional). E.g., files used by
        the `src` file via #include must be listed here.
      out: The output of p4check  (stdin & sterr) is written to this file.
      table_entries: Table entries in P4RT protobuf text format to be passed to
        `p4check` for constraint checking.
      visibility: Visibility of this target.
    """
    p4info_file = src + "info.txt"
    p4check = "@com_github_p4lang_p4_constraints//p4_constraints/cli:p4check"
    p4_library(
        name = name + "_p4info",
        visibility = visibility,
        src = src,
        deps = deps,
        p4info_out = p4info_file,
    )
    native.genrule(
        name = name,
        visibility = visibility,
        testonly = True,
        srcs = [p4info_file] + table_entries,
        outs = [out],
        tools = [p4check] + deps,
        cmd = """
            "{p4check}" --p4info=$(SRCS) &> $(OUTS) || true
        """.format(
            p4check = "$(execpath %s)" % p4check,
        ),
    )

def _diff_test_script(ctx):
    """Returns bash script to be executed by the diff_test target."""
    return """
if [[ "$1" == "--update" ]]; then
    cp -f "{actual}" "${{BUILD_WORKSPACE_DIRECTORY}}/{expected}"
fi

diff -u "{expected}" "{actual}"

if [[ $? = 0 ]]; then
    # Expected and actual agree.
    if [[ "$1" == "--update" ]]; then
        echo "Successfully updated: {expected}."
    else
        echo "PASSED"
    fi
    exit 0
else
    # Expected and actual disagree.
    if [[ "$1" == "--update" ]]; then
        echo "Failed to update: {expected}. Try updating manually."
    else
        cat << EOF

Output not as expected. To update $(basename {expected}), run the following command:
bazel run {target} -- --update
EOF
    fi
    exit 1
fi
    """.format(
        actual = ctx.file.actual.short_path,
        expected = ctx.file.expected.short_path,
        target = ctx.label,
    )

def _diff_test_impl(ctx):
    """Computes diff of two files, checking that they agree.

    When invoked as `bazel run <target> -- --update`, will update the `expected`
    file to match the contents of the `actual` file.
    """

    # Write test script that will be executed by 'bazel test'.
    ctx.actions.write(
        output = ctx.outputs.executable,
        content = _diff_test_script(ctx),
        is_executable = True,
    )

    # Make test script dependencies available at runtime.
    runfiles = [ctx.file.actual, ctx.file.expected]
    return DefaultInfo(
        runfiles = ctx.runfiles(files = runfiles),
    )

diff_test = rule(
    doc = """Computes diff of two files, checking that they agree.

    Typically used to test that the output of some command looks as expected.
    To update the expected file, run `bazel run <target> -- --update`.
    """,
    implementation = _diff_test_impl,
    test = True,
    attrs = {
        "actual": attr.label(
            doc = "'Actual' file, typically containing the output of some command.",
            mandatory = True,
            allow_single_file = True,
        ),
        "expected": attr.label(
            doc = """\
Expected file (aka golden file), containing the expected output.
To auto-generate or update, run `bazel run <target> -- --update`.
""",
            mandatory = True,
            allow_single_file = True,
        ),
    },
)

def cmd_diff_test(name, actual_cmd, expected, tools = [], data = [], visibility = None):
    """Runs a command to get the actual output, to compare against `expected`."""
    native.genrule(
        name = name + "_output",
        visibility = visibility,
        srcs = data,
        outs = [name + ".actual"],
        tools = tools,
        cmd = actual_cmd + " > '$@'",
        testonly = True,
    )
    diff_test(
        name = name,
        actual = name + ".actual",
        expected = expected,
    )
