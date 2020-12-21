"""Sets up 3rd party workspaces needed to compile p4_constraints."""

load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def p4_constraints_deps():
    """Sets up 3rd party workspaces needed to compile p4_constraints."""
    if not native.existing_rule("com_google_absl"):
        http_archive(
            name = "com_google_absl",
            url = "https://github.com/abseil/abseil-cpp/archive/20200225.2.tar.gz",
            strip_prefix = "abseil-cpp-20200225.2",
            sha256 = "f41868f7a938605c92936230081175d1eae87f6ea2c248f41077c8f88316f111",
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
            urls = ["https://github.com/google/googletest/archive/release-1.10.0.tar.gz"],
            strip_prefix = "googletest-release-1.10.0",
            sha256 = "9dc9157a9a1551ec7a7e43daea9a694a0bb5fb8bec81235d8a1e6ef64c716dcb",
        )
    if not native.existing_rule("com_google_protobuf"):
        http_archive(
            name = "com_google_protobuf",
            url = "https://github.com/protocolbuffers/protobuf/releases/download/v3.12.3/protobuf-all-3.12.3.tar.gz",
            strip_prefix = "protobuf-3.12.3",
            sha256 = "1a83f0525e5c8096b7b812181865da3c8637de88f9777056cefbf51a1eb0b83f",
        )
    if not native.existing_rule("com_googlesource_code_re2"):
        http_archive(
            name = "com_googlesource_code_re2",
            url = "https://github.com/google/re2/archive/2020-07-06.tar.gz",
            strip_prefix = "re2-2020-07-06",
            sha256 = "2e9489a31ae007c81e90e8ec8a15d62d58a9c18d4fd1603f6441ef248556b41f",
        )
    if not native.existing_rule("rules_proto"):
        http_archive(
            name = "rules_proto",
            urls = [
                "https://mirror.bazel.build/github.com/bazelbuild/rules_proto/archive/97d8af4dc474595af3900dd85cb3a29ad28cc313.tar.gz",
                "https://github.com/bazelbuild/rules_proto/archive/97d8af4dc474595af3900dd85cb3a29ad28cc313.tar.gz",
            ],
            strip_prefix = "rules_proto-97d8af4dc474595af3900dd85cb3a29ad28cc313",
            sha256 = "602e7161d9195e50246177e7c55b2f39950a9cf7366f74ed5f22fd45750cd208",
        )
    if not native.existing_rule("com_github_p4lang_p4runtime"):
        http_archive(
            name = "com_github_p4lang_p4runtime",
            urls = ["https://github.com/p4lang/p4runtime/archive/v1.2.0.tar.gz"],
            strip_prefix = "p4runtime-1.2.0/proto",
            sha256 = "92582fd514193bc40c841aa2b1fa80e4f1f8b618def974877de7b0f2de3e4be4",
        )
    if not native.existing_rule("com_github_p4lang_p4c"):
        git_repository(
            name = "com_github_p4lang_p4c",
            # Newest commit on master on 2020-07-08.
            commit = "17d1d55c8fa647eb6dd15141048c70d96def34a9",
            remote = "https://github.com/p4lang/p4c",
            shallow_since = "1594055738 -0700",
        )

def glog_build_file():
    """We use a custom BUILD files since we do not need gflags support."""
    return "\n".join([
        "load(':bazel/glog.bzl', 'glog_library')",
        "glog_library(with_gflags = False)",
    ])
