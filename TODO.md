* announce officially
* add support for source locations to p4c, see https://github.com/p4lang/p4runtime/issues/285;
  this will dramatically improve our error messages
* instead of using custom p4runtime BUILD, fix problems upstream
  -> this will make `bazel build //... && bazel test //...` possible
* continuous integration
  * remove METADATA file; look into way to run ClangTidy as CI
    - this turns out to be tricky as it requires a "compilation database", which are not officially suported by Bazel currently;
      see https://stackoverflow.com/questions/44966133/how-to-generate-compile-commands-json-for-a-c-bazel-project.
* remove system dependency on p4c; build using bazel instead.
