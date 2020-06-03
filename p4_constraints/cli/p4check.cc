// Copyright 2020 The P4-Constraints Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Usage: p4check --p4info=<file> [<table_entry_file> ...]
//
// Parses the table constraints in the given P4 program (in p4info.proto text
// format) and checks if the given table entries (in p4runtime.proto text
// format) satisfy the constraints imposed on their respective tables.
//
// This CLI is not intended for use in production; it is intended for testing
// and showcasing the p4_constraints library.

#include <fstream>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/flags/usage.h"
#include "absl/status/status.h"
#include "absl/strings/str_join.h"
#include "absl/types/span.h"
#include "absl/types/variant.h"
#include "google/protobuf/io/zero_copy_stream_impl.h"
#include "google/protobuf/text_format.h"
#include "p4/config/v1/p4info.pb.h"
#include "p4/v1/p4runtime.pb.h"
#include "p4_constraints/backend/constraint_info.h"
#include "p4_constraints/backend/interpreter.h"
#include "util/statusor.h"

using ::p4_constraints::ConstraintInfo;
using ::p4_constraints::EntryMeetsConstraint;
using ::p4_constraints::P4ToConstraintInfo;

ABSL_FLAG(std::string, p4info, "", "p4info file (required)");
constexpr char kUsage[] =
    "--p4info=<file> [<table entry file in P4RT protobuf format> ...]";

// The 8 most significant bits of any P4Runtime table ID must equal
// p4::config::v1::P4Ids::TABLE. To ease writing table entries by hand in
// testing, we simply coerce all table IDs into the correct format.
// See P4Runtime specification, "6.3 ID Allocation for P4Info Objects".
uint32 CoerceToTableId(uint32 table_id) {
  return (table_id & 0x00FFFFFF) | (p4::config::v1::P4Ids::TABLE << 24);
}

int main(int argc, char** argv) {
  const absl::string_view usage[] = {"usage:", argv[0], kUsage};
  absl::SetProgramUsageMessage(absl::StrJoin(usage, " "));
  std::vector<char*> positional_args = absl::ParseCommandLine(argc, argv);

  // Read p4info flag.
  const std::string p4info_filename = absl::GetFlag(FLAGS_p4info);
  if (p4info_filename.empty()) {
    std::cerr << "Missing argument: --p4info=<file>\n";
    return 1;
  }

  // Open p4info file.
  std::ifstream p4info_file(p4info_filename);
  if (!p4info_file.is_open()) {
    std::cerr << "Unable to open p4info file: " << p4info_filename << "\n";
    return 1;
  }

  // Parse p4info file.
  p4::config::v1::P4Info p4info;
  {
    google::protobuf::io::IstreamInputStream stream(&p4info_file);
    if (!google::protobuf::TextFormat::Parse(&stream, &p4info)) {
      std::cerr << "Unable to parse p4info file: " << p4info_filename << "\n";
      return 1;
    }
  }
  // p4c 2019 and earlier does not set the 8 most significant bits of table IDs
  // correctly, but p4c 2020 (since PR p4lang/p4c#2243) does. To make p4check
  // compatible with both, we coerce all table IDs into the right format here.
  for (auto& table : *p4info.mutable_tables()) {
    table.mutable_preamble()->set_id(CoerceToTableId(table.preamble().id()));
  }

  // Parse constraints and report potential errors.
  absl::variant<ConstraintInfo, std::vector<absl::Status>> info_or_errors =
      P4ToConstraintInfo(p4info);
  if (absl::holds_alternative<std::vector<absl::Status>>(info_or_errors)) {
    const auto& errors = absl::get<std::vector<absl::Status>>(info_or_errors);
    for (const absl::Status& error : errors) {
      std::cerr << error.message() << "\n\n";
    }
    return 1;
  }
  const auto& constraint_info = absl::get<ConstraintInfo>(info_or_errors);

  // Check table entries, if any where given.
  for (const char* entry_filename :
       absl::MakeSpan(positional_args).subspan(1)) {
    std::cout << entry_filename << ": ";

    // Open entry file.
    std::ifstream entry_file(entry_filename);
    if (!entry_file.is_open()) {
      std::cout << "not found\n\n";
      continue;
    }

    // Parse entry file.
    p4::v1::TableEntry entry;
    {
      google::protobuf::io::IstreamInputStream entry_stream(&entry_file);
      if (!google::protobuf::TextFormat::Parse(&entry_stream, &entry)) {
        std::cout << "unable to parse\n\n";
        continue;
      }
    }
    // For testing, it is convenient to write table entries whose table ID
    // matches the @id annotation of the corresponding table in the .p4 program.
    // However, p4c sets the 8 most significant bits of IDs from @id annotations
    // to p4::config::v1::P4Ids::TABLE, so we must do the same here.
    entry.set_table_id(CoerceToTableId(entry.table_id()));

    // Check entry.
    util::StatusOr<bool> result = EntryMeetsConstraint(entry, constraint_info);
    if (!result.ok()) {
      std::cout << "Error: " << result.status() << "\n\n";
      continue;
    }
    std::cout << "constraint "
              << (result.ValueOrDie() ? "satisfied" : "violated") << "\n\n";
  }

  return 0;
}
