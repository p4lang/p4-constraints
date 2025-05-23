![native build & test](https://github.com/p4lang/p4-constraints/workflows/native%20build%20&%20test/badge.svg)

# p4-constraints

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
   
**_Check out [these slides](docs/2020-08-17_LDWG.pdf) for a tour of p4-constraints (up to date as of May 2020)._**

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
requirement captures the intent of the P4 programmer that the ACL table
should not require general ternary matches on the destination address; the
constraint documents this intent and let's us catch accidental ternary matches
installed by the control plane at runtime.

## Example - Action Restrictions

An *action restriction* is similar to an entry restriction, but is placed on a
P4 action:
```p4
// Disallow multicast group ID 0, since it indicates "no multicast" in 
// `v1model.p4`.
@action_restriction("multicast_group_id != 0")
action multicast(bit<16> multicast_group_id) {
  standard_metadata.mcast_grp = multicast_group_id;
}
```

## API

At a high level, p4-constraint's API consists of only two functions:
one function for parsing constraints and one function for checking them.
```C++
/* p4_constraints/backend/constraint_info.h */

// Translates `P4Info` to `ConstraintInfo`.
//
// Parses all tables and actions and their p4-constraints annotations into an
// in-memory representation suitable for constraint checking. Returns parsed
// representation, or an error status if parsing fails.
absl::StatusOr<ConstraintInfo> P4ToConstraintInfo(
    const p4::config::v1::P4Info &p4info);
```
```C++
/* p4_constraints/backend/interpreter.h */

// Checks if a given table entry satisfies the constraints attached to its
// associated table/action.
//
// Returns the empty string if this is the case, or a human-readable nonempty
// string explaining why it is not the case otherwise. Returns an
// `InvalidArgument` if the entry's table or action is not defined in
// `ConstraintInfo`, or if `entry` is inconsistent with these definitions.
absl::StatusOr<std::string> ReasonEntryViolatesConstraint(
    const p4::v1::TableEntry& entry, const ConstraintInfo& constraint_info);
```
For those who seek more fine-grained control, the API also offers more
low-level functions that are documented in the various header files.

## Use cases

p4-constraints can be used as follows:

- As a specification language to further clarify the control plane API.
- In P4Runtime server implementations to reject ill-formed table entries.
- In the controller as a defense-in-depth check.
- During testing to check for valid vs invalid table entries.
  - To guide a fuzzer to valid table entries.

## Building

Building p4-constraints requires [Bazel](https://bazel.build/), a C++11 compiler
(or newer), and [GMP](https://gmplib.org/). The latter can be installed on
Ubuntu as follows:
```sh
apt-get install libgmp-dev
```

We inherit a few additional dependencies
([Bison](https://en.wikipedia.org/wiki/GNU_Bison) and
[Flex](https://en.wikipedia.org/wiki/Flex_\(lexical_analyser_generator\)))
from [p4c](https://github.com/p4lang/p4c); these are required for
[golden testing](#golden-tests) only and can be installed on Ubuntu as follows:
```sh
apt-get install bison flex libfl-dev
```

To build, run
```sh
bazel build //p4_constraints/...
```

To run all tests except [golden tests](#golden-tests), run
```sh
bazel test //p4_constraints/...
```

To run all tests including [golden tests](#golden-tests), run
```sh
bazel test //...
```
This may take a while when executed for the first time,
as it will build p4c from source.

To see the output of a failed test, invoke it using `bazel run` like so:
```sh
bazel run //p4_constraints/frontend:lexer_test
```

### MacOS

While building under MacOS is not officially supported, it currently works after
executing the following commands, using [Homebrew](https://brew.sh/) to install
[GMP](https://gmplib.org/):
```sh
# Install GMP.
brew install gmp && brew link gmp
# Tell linker (ld) where to find GMP so '-lgmp' works.
echo "build --linkopt='-L/usr/local/brew/lib'" > user.bazelrc
```

### Docker

You can also build p4-constraint in a Docker container, for example:
```sh
docker build --tag p4-constraints .                 # Time to get coffee...
docker run --tty --interactive p4-constraints bash  # Open shell in container.
bazel test //...                                    # Run tests in container.
```

## Golden tests

The easiest way to experiment with p4-constraints is to write a
[golden test](https://ro-che.info/articles/2017-12-04-golden-tests).
We provide [Bazel rules](e2e_tests/p4check.bzl) `run_p4check` and `diff_test` to
make this convenient.
See the [e2e_tests/](e2e_tests/) folder -- in particular
[e2e_tests/BUILD.bazel](e2e_tests/BUILD.bazel) -- for examples of how to use them.

To run all golden tests, execute
```sh
bazel test //e2e_tests/...
```
[Recall](#building) that this will build p4c and requires
[Bison](https://en.wikipedia.org/wiki/GNU_Bison) and
[Flex](https://en.wikipedia.org/wiki/Flex_\(lexical_analyser_generator\))
to be installed.

To see the output of a failed test, invoke it using `bazel run` like so:
```sh
bazel run //e2e_test:invalid_constraints_test
```

## p4check

The `p4check` CLI allows invoking the p4-constraints library from the command
line. The most convenient way to run `p4check` is using the
[`run_p4check`-rule](e2e_tests/p4check.bzl), as is done for
[golden testing](#golden-tests).

To learn how to invoke [p4check](p4_constraints/cli/p4check.cc) manually,
consult [the source file](p4_constraints/cli/p4check.cc) or run
```sh
bazel run p4_constraints/cli:p4check -- --help
```

## Constraint language

See [docs/language-specification.md](docs/language-specification.md) for a
documentation of the constraint languages, or look at some example constraints
in the .p4-files in the [e2e_tests folder](e2e_tests/).

## Contributing

Feedback, suggestions, and contributions in the form of GitHub issues and
[pull requests](CONTRIBUTING.md) are welcome and encouraged.

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

    SPDX-License-Identifier: Apache-2.0

This can be done automatically using
[addlicense](https://github.com/google/addlicense) as follows:
```sh
addlicense -c "The P4-Constraints Authors" -s -l apache ./p4_constraints
```
