"""Sets up 3rd party workspaces needed to compile p4_constraints."""

load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def p4_constraints_deps():
    """Sets up 3rd party workspaces needed to compile p4_constraints."""
    if not native.existing_rule("com_google_absl"):
        git_repository(
            name = "com_google_absl",
            remote = "https://github.com/abseil/abseil-cpp",
            commit = "78be63686ba732b25052be15f8d6dee891c05749",  # Abseil LTS 20230125
        )
    if not native.existing_rule("com_google_googletest"):
        http_archive(
            name = "com_google_googletest",
            urls = ["https://github.com/google/googletest/archive/refs/tags/v1.13.0.tar.gz"],
            strip_prefix = "googletest-1.13.0",
        )
    if not native.existing_rule("com_google_protobuf"):
        http_archive(
            name = "com_google_protobuf",
            url = "https://github.com/protocolbuffers/protobuf/releases/download/v22.2/protobuf-22.2.tar.gz",
            strip_prefix = "protobuf-22.2",
            sha256 = "1ff680568f8e537bb4be9813bac0c1d87848d5be9d000ebe30f0bc2d7aabe045",
        )
    if not native.existing_rule("com_googlesource_code_re2"):
        git_repository(
            name = "com_googlesource_code_re2",
            # Newest commit on `abseil` branch on 2023-03-15.
            commit = "da6f4cbe782f33b012604d009235334cc728ccbd",
            remote = "https://github.com/google/re2",
        )
    if not native.existing_rule("rules_proto"):
        http_archive(
            name = "rules_proto",
            sha256 = "dc3fb206a2cb3441b485eb1e423165b231235a1ea9b031b4433cf7bc1fa460dd",
            strip_prefix = "rules_proto-5.3.0-21.7",
            urls = [
                "https://github.com/bazelbuild/rules_proto/archive/refs/tags/5.3.0-21.7.tar.gz",
            ],
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
