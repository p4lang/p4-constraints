# p4-constraints

TODO: integrate CLI status here

**Work in progress. Feedback and contributions are welcome.**

p4-constraints extends the [P4 language](https://p4.org/) with support for
constraint
[annotations](https://p4.org/p4-spec/docs/P4-16-v1.2.0.html#sec-annotations).
These constraints can be enforced at runtime using the p4-constraints library.

The project currently provides two main artifacts:

1. A [C++ library](p4_constraints/) for parsing and checking constraints.
2. A [command line interface (CLI)](p4_constraints/cli) that takes as input a P4
   program with constraints and a set of table entries, and reports if the table
   entries satisfy the constraints placed on their respective tables or not.
   (Note that the CLI is intended for testing and experimentation, not for
   production use.)

## Example - Entry Restrictions

An *entry restriction* is a constraint specifying what entries are allowed to be
placed in a P4 table. Here is an example:
```p4
@entry_restriction("
  // Only match on IPv4 addresses of IPv4 packets.
  hdr.ipv4.dst_addr::mask != 0 ->
    hdr.ethernet.ether_type == IPv4_ETHER_TYPE;

  // Only match on IPv6 addresses of IPv6 packets.
  hdr.ipv6.dst_addr::mask != 0 ->
    hdr.ethernet.ether_type == IPv6_ETHER_TYPE;

  // Either wildcard or exact match (i.e., "optional" match).
  hdr.ipv4.dst_addr::mask == 0 || hdr.ipv4.dst_addr::mask == -1;
")
table acl_table {
  key = {
    hdr.ethernet.ether_type : ternary;
    hdr.ethernet.src_addr : ternary;
    hdr.ipv4.dst_addr : ternary;
    standard_metadata.ingress_port: ternary;
    hdr.ipv6.dst_addr : ternary;
    hdr.ipv4.src_addr : ternary;
    local_metadata.dscp : ternary;
    local_metadata.is_ip_packet : ternary;
  }
  actions = { ... }
}
```
The `@entry_restriction` says that a valid ACL table entry must meet
three requirements:

1. It can only match on the IPv4 destination address of IPv4 packets.
2. It can only match on the IPv6 destination address of IPv6 packets.
3. It can only perform a wildcard or an exact match on the IPv4 address.

The first two requirements are to rule out undefined behavior. The third
requirement captures the intend of the P4 programmer that the ACL table
should not require general ternary matches on the destination address; the
constraint documents this intend and let's us catch accidental ternary matches
installed by the control plane at runtime.

## Building

Building p4-constraints requires [Bazel](https://bazel.build/), a C++11 compiler
(or newer), and [GMP](https://gmplib.org/). The latter can be installed on
Ubuntu as follows:
```sh
apt-get install libgmp-dev
```

Ensure that all [third-party dependencies](third_party/) are checked out:
```sh
git submodule update --init --recursive
```

To build, run
```sh
bazel build //p4_contraints/...
```

To test, run
```sh
bazel test //p4_contraints/...
```

## Golden tests

The easiest way to experiment with p4-constraints is to write a
[golden test](https://ro-che.info/articles/2017-12-04-golden-tests).
We provide [Bazel rules](test/p4check.bzl) `run_p4check` and `diff_test` to make
this convenient.
See the [test/](test/) folder for examples.

Currently, the golden tests require [p4c](git@github.com:p4lang/p4c.git) as
a system dependency (we hope to make this a source dependency in the future):
```sh
which p4c  # This needs to succeed for golden tests to work.
```

To run all golden tests, execute
```sh
bazel test //test/...  # TODO: Porting to GitHub caused some of these to break.
```

## p4check

The `p4check` CLI allows invoking the p4-constraints library from the command
line. The most convenient way to run `p4check` is using the
[`run_p4check`-rule](test/p4check.bzl), as is done for
[golden testing](#golden-tests).

To learn how to invoke [p4check](p4_constraints/cli/p4check.cc) manually,
consult [the source file](p4_constraints/cli/p4check.cc) or run
```sh
bazel run p4_constraints/cli:p4check -- --help
```

## Constraint language
TODO: Write a little specification.

## Contributing

Feedback, suggestions, and contributions in the form of GitHub issues and pull
requests are welcome and encouraged.

### Source Code Headers

Please note that every file containing source code must include the following
copyright header:

    Copyright 2020 The P4-Constraints Authors
    
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at
    
        https://www.apache.org/licenses/LICENSE-2.0
    
    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

This can be done automatically using
[addlicense](https://github.com/google/addlicense) as follows:
```sh
addlicense -c "The P4-Constraints Authors" -l apache ./p4_constraints
```