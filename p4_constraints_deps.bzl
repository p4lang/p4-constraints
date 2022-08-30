"""Sets up 3rd party workspaces needed to compile p4_constraints."""

load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def p4_constraints_deps():
    """Sets up 3rd party workspaces needed to compile p4_constraints."""
    if not native.existing_rule("com_google_absl"):
        # Newest release(20220623.1) does not support absl log so latest newest commit is used.
        git_repository(
            name = "com_google_absl",
            # Newest commit on main branch 2022-09-01.
            commit = "fa108c444f18f6345b78090af47ec5fb4a7c2c36",
            remote = "https://github.com/abseil/abseil-cpp/",
        )
    if not native.existing_rule("com_github_google_glog"):
        http_archive(
            name = "com_github_google_glog",
            urls = ["https://github.com/google/glog/archive/v0.4.0.tar.gz"],
            strip_prefix = "glog-0.4.0",
            sha256 = "f28359aeba12f30d73d9e4711ef356dc842886968112162bc73002645139c39c",
            build_file_content = glog_build_file(),
        )
    if not native.existing_rule("com_google_googletest"):
        http_archive(
            name = "com_google_googletest",
            urls = ["https://github.com/google/googletest/archive/release-1.11.0.tar.gz"],
            strip_prefix = "googletest-release-1.11.0",
            sha256 = "b4870bf121ff7795ba20d20bcdd8627b8e088f2d1dab299a031c1034eddc93d5",
        )
    if not native.existing_rule("com_google_protobuf"):
        http_archive(
            name = "com_google_protobuf",
            url = "https://github.com/protocolbuffers/protobuf/releases/download/v21.5/protobuf-all-21.5.tar.gz",
            strip_prefix = "protobuf-21.5",
            sha256 = "7ba0cb2ecfd9e5d44a6fa9ce05f254b7e5cd70ec89fafba0b07448f3e258310c",
        )
    if not native.existing_rule("com_googlesource_code_re2"):
        git_repository(
            name = "com_googlesource_code_re2",
            # Newest commit on `abseil` branch on 2022-09-01.
            commit = "8c0f7738d67b1808f9bb9a93a5cdc6d33d50ede9",
            remote = "https://github.com/google/re2",
            shallow_since = "1661542054 +0000",
        )
    if not native.existing_rule("rules_proto"):
        http_archive(
            name = "rules_proto",
            urls = [
                "https://github.com/bazelbuild/rules_proto/archive/refs/tags/4.0.0-3.20.0.tar.gz",
            ],
            strip_prefix = "rules_proto-4.0.0-3.20.0",
            sha256 = "e017528fd1c91c5a33f15493e3a398181a9e821a804eb7ff5acdd1d2d6c2b18d",
        )
    if not native.existing_rule("com_github_p4lang_p4runtime"):
        http_archive(
            name = "com_github_p4lang_p4runtime",
            urls = ["https://github.com/p4lang/p4runtime/archive/refs/tags/v1.3.0.tar.gz"],
            strip_prefix = "p4runtime-1.3.0/proto",
            sha256 = "09d826e868b1c18e47ff1b5c3d9c6afc5fa7b7a3f856f9d2d9273f38f4fc87e2",
        )
    if not native.existing_rule("com_github_p4lang_p4c"):
        http_archive(
            name = "com_github_p4lang_p4c",
            # Newest commit on main on 2021-12-07.
            url = "https://github.com/p4lang/p4c/archive/a9aa5ff46affe8fd5dde78c2411d1bc58a715b33.zip",
            strip_prefix = "p4c-a9aa5ff46affe8fd5dde78c2411d1bc58a715b33",
            sha256 = "fa22c3d2b3105a39a73fc3938cbc6cd5d7895113a3e6ed6c5a48fbbd958a28af",
        )

def glog_build_file():
    """We use a custom BUILD files since we do not need gflags support."""
    return "\n".join([
        "load(':bazel/glog.bzl', 'glog_library')",
        "glog_library(with_gflags = False)",
    ])
