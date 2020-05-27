* make `bazel test //test/...` pass
* remove system dependency on p4c; build using bazel instead.
* instead of using custom p4runtime BUILD, fix problems upstream
  -> this will make `bazel build //... && bazel test //...` possible
* remove METADATA file; look into way to run ClangTidy as CI
* finish README
* continuous integration
* announce officially
* Some dependencies are not locked to a specific version. This will cause
  breakage in the future. Fix this.
* Couldn't figure out how to build GMP with bazel, so for now this is a system
  dependency. This is not ideal, but may be okay since it is also true for p4c.
