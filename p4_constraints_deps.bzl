"""Sets up 3rd party workspaces needed to compile p4_constraints."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

def p4_constraints_deps():
    """Sets up 3rd party workspaces needed to compile p4_constraints."""
    if not native.existing_rule("com_google_absl"):
        http_archive(
            name = "com_google_absl",
            url = "https://github.com/abseil/abseil-cpp/releases/download/20240116.2/abseil-cpp-20240116.2.tar.gz",
            strip_prefix = "abseil-cpp-20240116.2",
            sha256 = "733726b8c3a6d39a4120d7e45ea8b41a434cdacde401cba500f14236c49b39dc",
        )
    if not native.existing_rule("bazel_skylib"):
        http_archive(
            name = "bazel_skylib",
            url = "https://github.com/bazelbuild/bazel-skylib/releases/download/1.9.0/bazel-skylib-1.9.0.tar.gz",
            sha256 = "3b5b49006181f5f8ff626ef8ddceaa95e9bb8ad294f7b5d7b11ea9f7ddaf8c59",
        )
    if not native.existing_rule("com_google_gutil"):
        http_archive(
            name = "com_google_gutil",
            url = "https://github.com/google/gutil/archive/16283826f41a6d4301a7c42abb07d0c8aaeec452.tar.gz",
            strip_prefix = "gutil-16283826f41a6d4301a7c42abb07d0c8aaeec452",
            sha256 = "c470e5e017e0a9b341c445d1edc8df3e11d54b6286dcba74e9128118ac0d3653",
        )
    if not native.existing_rule("com_google_googletest"):
        http_archive(
            name = "com_google_googletest",
            url = "https://github.com/google/googletest/releases/download/v1.17.0/googletest-1.17.0.tar.gz",
            strip_prefix = "googletest-1.17.0",
            sha256 = "65fab701d9829d38cb77c14acdc431d2108bfdbf8979e40eb8ae567edf10b27c",
        )
    if not native.existing_rule("com_google_protobuf"):
        http_archive(
            name = "com_google_protobuf",
            url = "https://github.com/protocolbuffers/protobuf/releases/download/v28.2/protobuf-28.2.tar.gz",
            strip_prefix = "protobuf-28.2",
            sha256 = "b2340aa47faf7ef10a0328190319d3f3bee1b24f426d4ce8f4253b6f27ce16db",
        )
    if not native.existing_rule("com_github_grpc_grpc"):
        http_archive(
            name = "com_github_grpc_grpc",
            url = "https://github.com/grpc/grpc/archive/v1.63.0.zip",
            strip_prefix = "grpc-1.63.0",
            sha256 = "daa1b06a19b5f7e4603e1f8980eeab43cf69b6e89bee3b2547f275fa5af7f480",
        )
    if not native.existing_rule("com_google_googleapis"):
        http_archive(
            name = "com_google_googleapis",
            url = "https://github.com/googleapis/googleapis/archive/f405c718d60484124808adb7fb5963974d654bb4.zip",
            strip_prefix = "googleapis-f405c718d60484124808adb7fb5963974d654bb4",
            sha256 = "406b64643eede84ce3e0821a1d01f66eaf6254e79cb9c4f53be9054551935e79",
        )
    if not native.existing_rule("com_googlesource_code_re2"):
        http_archive(
            name = "com_googlesource_code_re2",
            url = "https://github.com/google/re2/archive/2023-06-01.tar.gz",
            strip_prefix = "re2-2023-06-01",
            sha256 = "8b4a8175da7205df2ad02e405a950a02eaa3e3e0840947cd598e92dca453199b",
        )
    # rules_proto is provided transitively by protobuf_deps().
    if not native.existing_rule("com_github_p4lang_p4runtime"):
        http_archive(
            name = "com_github_p4lang_p4runtime",
            url = "https://github.com/p4lang/p4runtime/archive/bd2a626484e125da30422326d27fad0ddebdd645.tar.gz",
            strip_prefix = "p4runtime-bd2a626484e125da30422326d27fad0ddebdd645/proto",
            sha256 = "5cad9290fce6748ef3e76a857f9d2cb6747ec3540423a325eff61a718d464cfd",
        )
    if not native.existing_rule("com_github_p4lang_p4c"):
        http_archive(
            name = "com_github_p4lang_p4c",
            url = "https://github.com/p4lang/p4c/archive/df264349e4216f08275c1c71a532f631df9b5666.tar.gz",
            strip_prefix = "p4c-df264349e4216f08275c1c71a532f631df9b5666",
            sha256 = "2f185be689a72f4df4f355dd80a0f3ccc0e984a794605d782d0a9b3a151eb7ec",
        )
    if not native.existing_rule("com_github_z3prover_z3"):
        http_archive(
            name = "com_github_z3prover_z3",
            url = "https://github.com/Z3Prover/z3/archive/z3-4.8.12.tar.gz",
            strip_prefix = "z3-z3-4.8.12",
            sha256 = "e3aaefde68b839299cbc988178529535e66048398f7d083b40c69fe0da55f8b7",
            build_file = "@//:bazel/BUILD.z3.bazel",
        )
    if not native.existing_rule("rules_cc"):
        http_archive(
            name = "rules_cc",
            url = "https://github.com/bazelbuild/rules_cc/releases/download/0.1.5/rules_cc-0.1.5.tar.gz",
            strip_prefix = "rules_cc-0.1.5",
            sha256 = "b8b918a85f9144c01f6cfe0f45e4f2838c7413961a8ff23bc0c6cdf8bb07a3b6",
        )
    if not native.existing_rule("rules_license"):
        http_archive(
            name = "rules_license",
            url = "https://github.com/bazelbuild/rules_license/releases/download/1.0.0/rules_license-1.0.0.tar.gz",
            sha256 = "26d4021f6898e23b82ef953078389dd49ac2b5618ac564ade4ef87cced147b38",
        )
    if not native.existing_rule("rules_foreign_cc"):
        http_archive(
            name = "rules_foreign_cc",
            url = "https://github.com/bazelbuild/rules_foreign_cc/releases/download/0.14.0/rules_foreign_cc-0.14.0.tar.gz",
            strip_prefix = "rules_foreign_cc-0.14.0",
            sha256 = "e0f0ebb1a2223c99a904a565e62aa285bf1d1a8aeda22d10ea2127591624866c",
        )
    if not native.existing_rule("com_github_nelhage_rules_boost"):
        http_archive(
            name = "com_github_nelhage_rules_boost",
            url = "https://github.com/nelhage/rules_boost/archive/5160325dbdc8c9e499f9d9917d913f35f1785d52.zip",
            strip_prefix = "rules_boost-5160325dbdc8c9e499f9d9917d913f35f1785d52",
            sha256 = "feb4b1294684c79df7c1e08f1aec5da0da52021e33db59c88edbe86b4d1a017a",
        )
