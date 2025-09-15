"""Sets up 3rd party workspaces needed to compile p4_constraints."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def p4_constraints_deps():
    """Sets up 3rd party workspaces needed to compile p4_constraints."""
    if not native.existing_rule("com_google_absl"):
        http_archive(
            name = "com_google_absl",
            urls = ["https://github.com/abseil/abseil-cpp/releases/download/20240722.0/abseil-cpp-20240722.0.tar.gz"],
            strip_prefix = "abseil-cpp-20240722.0",
        )
    if not native.existing_rule("com_google_gutil"):
        http_archive(
            name = "com_google_gutil",
            # Newest commit on main as of 2025-05-14.
            url = "https://github.com/google/gutil/archive/d2f1bdd819287c3951adaba5ea6e5426d2eefff1.zip",
            strip_prefix = "gutil-d2f1bdd819287c3951adaba5ea6e5426d2eefff1",
            sha256 = "033bcab2835a0aea0427d38503f5ae2bd478af134ab8f3e75b65d2cd444ac8ca",
        )
    if not native.existing_rule("com_google_googletest"):
        http_archive(
            name = "com_google_googletest",
            urls = ["https://github.com/google/googletest/releases/download/v1.15.2/googletest-1.15.2.tar.gz"],
            strip_prefix = "googletest-1.15.2",
        )
    if not native.existing_rule("com_google_protobuf"):
        http_archive(
            name = "com_google_protobuf",
            url = "https://github.com/protocolbuffers/protobuf/archive/refs/tags/v25.2.zip",
            strip_prefix = "protobuf-25.2",
            sha256 = "ddd0f5271f31b549efc74eb39061e142132653d5d043071fcec265bd571e73c4",
        )
    if not native.existing_rule("com_googlesource_code_re2"):
        http_archive(
            name = "com_googlesource_code_re2",
            url = "https://github.com/google/re2/releases/download/2024-02-01/re2-2024-02-01.tar.gz",
            strip_prefix = "re2-2024-02-01",
        )
    if not native.existing_rule("rules_proto"):
        http_archive(
            name = "rules_proto",
            url = "https://github.com/bazelbuild/rules_proto/archive/5.3.0-21.7.tar.gz",
            strip_prefix = "rules_proto-5.3.0-21.7",
            sha256 = "dc3fb206a2cb3441b485eb1e423165b231235a1ea9b031b4433cf7bc1fa460dd",
        )
    if not native.existing_rule("com_github_p4lang_p4runtime"):
        http_archive(
            name = "com_github_p4lang_p4runtime",
            urls = ["https://github.com/p4lang/p4runtime/archive/970cbdc1d8663356214d33e3ba213cb91676b491.tar.gz"],
            strip_prefix = "p4runtime-970cbdc1d8663356214d33e3ba213cb91676b491/proto",
        )
    if not native.existing_rule("com_github_p4lang_p4c"):
        http_archive(
            name = "com_github_p4lang_p4c",
            # Newest commit on main on 2021-12-07.
            url = "https://github.com/p4lang/p4c/archive/80629201abb61d9172639fefc7bb5b9d6007db08.zip",
            strip_prefix = "p4c-80629201abb61d9172639fefc7bb5b9d6007db08",
        )
    if not native.existing_rule("com_github_z3prover_z3"):
        http_archive(
            name = "com_github_z3prover_z3",
            url = "https://github.com/Z3Prover/z3/archive/z3-4.8.12.tar.gz",
            strip_prefix = "z3-z3-4.8.12",
            sha256 = "e3aaefde68b839299cbc988178529535e66048398f7d083b40c69fe0da55f8b7",
            build_file = "@//:bazel/BUILD.z3.bazel",
        )
    if not native.existing_rule("rules_foreign_cc"):  # Required for Z3.
        http_archive(
            name = "rules_foreign_cc",
            sha256 = "d54742ffbdc6924f222d2179f0e10e911c5c659c4ae74158e9fe827aad862ac6",
            strip_prefix = "rules_foreign_cc-0.2.0",
            url = "https://github.com/bazelbuild/rules_foreign_cc/archive/0.2.0.tar.gz",
        )
