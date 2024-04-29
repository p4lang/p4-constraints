#include "p4_constraints/backend/symbolic_interpreter.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "gutils/parse_text_proto.h"
#include "gutils/protocol_buffer_matchers.h"
#include "gutils/status_matchers.h"
#include "gutils/testing.h"
#include "p4/v1/p4runtime.pb.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/backend/constraint_info.h"
#include "p4_constraints/backend/interpreter.h"
#include "p4_constraints/backend/type_checker.h"
#include "p4_constraints/constraint_source.h"
#include "p4_constraints/frontend/constraint_kind.h"
#include "p4_constraints/frontend/parser.h"
#include "z3++.h"

namespace p4_constraints {
namespace {

using ::gutils::ParseTextProtoOrDie;
using ::gutils::SnakeCaseToCamelCase;
using ::gutils::testing::EqualsProto;
using ::gutils::testing::proto::IgnoringRepeatedFieldOrdering;
using ::gutils::testing::status::IsOk;
using ::gutils::testing::status::IsOkAndHolds;
using ::gutils::testing::status::StatusIs;
using ::p4_constraints::ast::Expression;
using ::p4_constraints::ast::Type;
using ::p4_constraints::internal_interpreter::AddSymbolicKey;
using ::p4_constraints::internal_interpreter::AddSymbolicPriority;
using ::p4_constraints::internal_interpreter::EvaluateConstraintSymbolically;
using ::testing::Not;

// Tests basic properties with a suite of simple test cases.
using SymbolicInterpreterTest = testing::TestWithParam<KeyInfo>;

// Tests invalid keys for AddSymbolicKey.
using AddSymbolicKeyNegativeTest = testing::TestWithParam<KeyInfo>;

TEST_P(SymbolicInterpreterTest, AddSymbolicKeyIsOkAndSatisfiable) {
  z3::context solver_context;
  z3::solver solver(solver_context);

  ASSERT_OK(AddSymbolicKey(/*key=*/GetParam(), solver));
  EXPECT_EQ(solver.check(), z3::sat);
}

TEST_P(SymbolicInterpreterTest, GetValueIsOk) {
  z3::context solver_context;
  z3::solver solver(solver_context);

  ASSERT_OK_AND_ASSIGN(SymbolicKey key,
                       AddSymbolicKey(/*key=*/GetParam(), solver));
  EXPECT_OK(GetValue(key));
}

TEST_P(SymbolicInterpreterTest, GetMaskIsOnlyOkForTernaryAndOptional) {
  z3::context solver_context;
  z3::solver solver(solver_context);

  KeyInfo key_info = GetParam();

  ASSERT_OK_AND_ASSIGN(SymbolicKey key, AddSymbolicKey(key_info, solver));
  if (key_info.type.has_ternary() || key_info.type.has_optional_match()) {
    EXPECT_OK(GetMask(key));
  } else {
    EXPECT_THAT(GetMask(key), StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST_P(SymbolicInterpreterTest, GetPrefixLengthIsOnlyOkForLpm) {
  z3::context solver_context;
  z3::solver solver(solver_context);

  KeyInfo key_info = GetParam();

  ASSERT_OK_AND_ASSIGN(SymbolicKey key, AddSymbolicKey(key_info, solver));
  if (key_info.type.has_lpm()) {
    EXPECT_OK(GetPrefixLength(key));
  } else {
    EXPECT_THAT(GetPrefixLength(key),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

INSTANTIATE_TEST_SUITE_P(
    AddSymbolicKeyBasicTests, SymbolicInterpreterTest,
    testing::ValuesIn(std::vector<KeyInfo>{
        // Basic tests for each key type.
        {
            .id = 1,
            .name = "exact32",
            .type = ParseTextProtoOrDie<ast::Type>("exact { bitwidth: 32 }"),
        },
        {
            .id = 2,
            .name = "optional32",
            .type = ParseTextProtoOrDie<ast::Type>(
                "optional_match { bitwidth: 32 }"),
        },
        {
            .id = 3,
            .name = "ternary32",
            .type = ParseTextProtoOrDie<ast::Type>("ternary { bitwidth: 32 }"),
        },
        {
            .id = 1,
            .name = "lpm32",
            .type = ParseTextProtoOrDie<ast::Type>("lpm { bitwidth: 32 }"),
        },

        // Keys with different bitwidths.
        {
            .id = 1,
            .name = "optional2",
            .type = ParseTextProtoOrDie<ast::Type>(
                "optional_match { bitwidth: 2 }"),
        },
        {
            .id = 1,
            .name = "ternary128",
            .type = ParseTextProtoOrDie<ast::Type>("ternary { bitwidth: 128 }"),
        },
        {
            .id = 1,
            .name = "lpm128",
            .type = ParseTextProtoOrDie<ast::Type>("lpm { bitwidth: 128 }"),
        },
    }),
    [](const testing::TestParamInfo<KeyInfo>& info) {
      return SnakeCaseToCamelCase(info.param.name);
    });

TEST_P(AddSymbolicKeyNegativeTest, AddSymbolicKeyReturnsStatus) {
  z3::context solver_context;
  z3::solver solver(solver_context);

  EXPECT_THAT(AddSymbolicKey(/*key=*/GetParam(), solver), Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(
    AddSymbolicKeyInvalidityTests, AddSymbolicKeyNegativeTest,
    testing::ValuesIn(std::vector<KeyInfo>{
        {
            .id = 1,
            .name = "zero_bitwidth_key",
            .type = ParseTextProtoOrDie<ast::Type>("exact { bitwidth: 0 }"),
        },
        {
            .id = 1,
            .name = "non_match_key_with_bitwidth",
            .type = ParseTextProtoOrDie<ast::Type>(
                "fixed_unsigned { bitwidth: 10 }"),
        },
        {
            .id = 1,
            .name = "non_match_key_without_bitwidth",
            .type = ParseTextProtoOrDie<ast::Type>("boolean {}"),
        },
    }),
    [](const testing::TestParamInfo<KeyInfo>& info) {
      return SnakeCaseToCamelCase(info.param.name);
    });

TEST(AddSymbolicKeySensibleConstraintsTest, OptionalCanHaveZeroMask) {
  z3::context solver_context;
  z3::solver solver(solver_context);

  KeyInfo optional_key_info{
      .id = 1,
      .name = "optional32",
      .type = ParseTextProtoOrDie<Type>("optional_match { bitwidth: 32 }"),
  };

  ASSERT_OK_AND_ASSIGN(SymbolicKey key,
                       AddSymbolicKey(optional_key_info, solver));
  ASSERT_OK_AND_ASSIGN(z3::expr mask, GetMask(key));
  solver.add(mask == 0x0);
  EXPECT_EQ(solver.check(), z3::sat);
}

TEST(AddSymbolicKeySensibleConstraintsTest, OptionalCanHaveFullMask) {
  z3::context solver_context;
  z3::solver solver(solver_context);

  KeyInfo optional_key_info{
      .id = 1,
      .name = "optional32",
      .type = ParseTextProtoOrDie<Type>("optional_match { bitwidth: 32 }"),
  };

  ASSERT_OK_AND_ASSIGN(SymbolicKey key,
                       AddSymbolicKey(optional_key_info, solver));
  ASSERT_OK_AND_ASSIGN(z3::expr mask, GetMask(key));
  // This needs to be disambiguated from an unsigned integer and thus
  // constructed separately.
  z3::expr all_ones_mask = solver_context.bv_val(0xFFFF'FFFF, 32);
  solver.add(mask == all_ones_mask);
  EXPECT_EQ(solver.check(), z3::sat);
}

TEST(AddSymbolicKeySensibleConstraintsTest, OptionalCantHaveArbitraryMask) {
  z3::context solver_context;
  z3::solver solver(solver_context);

  KeyInfo optional_key_info{
      .id = 1,
      .name = "optional32",
      .type = ParseTextProtoOrDie<Type>("optional_match { bitwidth: 32 }"),
  };

  ASSERT_OK_AND_ASSIGN(SymbolicKey key,
                       AddSymbolicKey(optional_key_info, solver));
  ASSERT_OK_AND_ASSIGN(z3::expr mask, GetMask(key));
  solver.add(mask == 0x10);
  EXPECT_EQ(solver.check(), z3::unsat);
}

TEST(AddSymbolicKeySensibleConstraintsTest,
     OptionalCantHaveSetBitsInValueNotSetInMask) {
  z3::context solver_context;
  z3::solver solver(solver_context);

  KeyInfo optional_key_info{
      .id = 1,
      .name = "optional32",
      .type = ParseTextProtoOrDie<Type>("optional_match { bitwidth: 32 }"),
  };

  ASSERT_OK_AND_ASSIGN(SymbolicKey key,
                       AddSymbolicKey(optional_key_info, solver));
  ASSERT_OK_AND_ASSIGN(z3::expr value, GetValue(key));
  ASSERT_OK_AND_ASSIGN(z3::expr mask, GetMask(key));
  solver.add(value == 0xF00F00);
  solver.add(mask == 0x0);
  EXPECT_EQ(solver.check(), z3::unsat);
}

TEST(AddSymbolicKeySensibleConstraintsTest, TernaryCanHaveZeroMask) {
  z3::context solver_context;
  z3::solver solver(solver_context);

  KeyInfo ternary_key_info{
      .id = 1,
      .name = "ternary32",
      .type = ParseTextProtoOrDie<Type>("ternary { bitwidth: 32 }"),
  };

  ASSERT_OK_AND_ASSIGN(SymbolicKey key,
                       AddSymbolicKey(ternary_key_info, solver));
  ASSERT_OK_AND_ASSIGN(z3::expr mask, GetMask(key));
  solver.add(mask == 0x0);
  EXPECT_EQ(solver.check(), z3::sat);
}

TEST(AddSymbolicKeySensibleConstraintsTest, TernaryCanHaveFullMask) {
  z3::context solver_context;
  z3::solver solver(solver_context);

  KeyInfo ternary_key_info{
      .id = 1,
      .name = "ternary32",
      .type = ParseTextProtoOrDie<Type>("ternary { bitwidth: 32 }"),
  };

  ASSERT_OK_AND_ASSIGN(SymbolicKey key,
                       AddSymbolicKey(ternary_key_info, solver));
  ASSERT_OK_AND_ASSIGN(z3::expr mask, GetMask(key));
  // This needs to be disambiguated from an unsigned integer and thus
  // constructed separately.
  z3::expr all_ones_mask = solver_context.bv_val(0xFFFF'FFFF, 32);
  solver.add(mask == all_ones_mask);
  EXPECT_EQ(solver.check(), z3::sat);
}

TEST(AddSymbolicKeySensibleConstraintsTest, TernaryCanHaveArbitraryMask) {
  z3::context solver_context;
  z3::solver solver(solver_context);

  KeyInfo ternary_key_info{
      .id = 1,
      .name = "ternary32",
      .type = ParseTextProtoOrDie<Type>("ternary { bitwidth: 32 }"),
  };

  ASSERT_OK_AND_ASSIGN(SymbolicKey key,
                       AddSymbolicKey(ternary_key_info, solver));
  ASSERT_OK_AND_ASSIGN(z3::expr mask, GetMask(key));
  solver.add(mask == 0x10);
  EXPECT_EQ(solver.check(), z3::sat);
}

TEST(AddSymbolicKeySensibleConstraintsTest,
     TernaryCantHaveSetBitsInValueNotSetInMask) {
  z3::context solver_context;
  z3::solver solver(solver_context);

  KeyInfo ternary_key_info{
      .id = 1,
      .name = "ternary32",
      .type = ParseTextProtoOrDie<Type>("ternary { bitwidth: 32 }"),
  };

  ASSERT_OK_AND_ASSIGN(SymbolicKey key,
                       AddSymbolicKey(ternary_key_info, solver));
  ASSERT_OK_AND_ASSIGN(z3::expr value, GetValue(key));
  ASSERT_OK_AND_ASSIGN(z3::expr mask, GetMask(key));
  solver.add(value == 0xF00F00);
  solver.add(mask == 0xF00E00);
  EXPECT_EQ(solver.check(), z3::unsat);
}

TEST(AddSymbolicKeySensibleConstraintsTest,
     TernaryCanHaveSetBitsInMaskNotSetInValue) {
  z3::context solver_context;
  z3::solver solver(solver_context);

  KeyInfo ternary_key_info{
      .id = 1,
      .name = "ternary32",
      .type = ParseTextProtoOrDie<Type>("ternary { bitwidth: 32 }"),
  };

  ASSERT_OK_AND_ASSIGN(SymbolicKey key,
                       AddSymbolicKey(ternary_key_info, solver));
  ASSERT_OK_AND_ASSIGN(z3::expr value, GetValue(key));
  ASSERT_OK_AND_ASSIGN(z3::expr mask, GetMask(key));
  solver.add(value == 0xF00E00);
  solver.add(mask == 0xF00F00);
  EXPECT_EQ(solver.check(), z3::sat);
}

TEST(AddSymbolicKeySensibleConstraintsTest, LpmCanHavePrefixLengthZero) {
  z3::context solver_context;
  z3::solver solver(solver_context);

  KeyInfo lpm_key_info{
      .id = 1,
      .name = "lpm32",
      .type = ParseTextProtoOrDie<Type>("lpm { bitwidth: 32 }"),
  };

  ASSERT_OK_AND_ASSIGN(SymbolicKey key, AddSymbolicKey(lpm_key_info, solver));
  ASSERT_OK_AND_ASSIGN(z3::expr prefix_length, GetPrefixLength(key));
  solver.add(prefix_length == 0);
  EXPECT_EQ(solver.check(), z3::sat);
}

TEST(AddSymbolicKeySensibleConstraintsTest, LpmCanHavePrefixLengthOfBitwidth) {
  z3::context solver_context;
  z3::solver solver(solver_context);

  KeyInfo lpm_key_info{
      .id = 1,
      .name = "lpm32",
      .type = ParseTextProtoOrDie<Type>("lpm { bitwidth: 32 }"),
  };

  ASSERT_OK_AND_ASSIGN(SymbolicKey key, AddSymbolicKey(lpm_key_info, solver));
  ASSERT_OK_AND_ASSIGN(z3::expr prefix_length, GetPrefixLength(key));
  solver.add(prefix_length == 32);
  EXPECT_EQ(solver.check(), z3::sat);
}

TEST(AddSymbolicKeySensibleConstraintsTest,
     LpmCanHavePrefixLengthWithinBitwidth) {
  z3::context solver_context;
  z3::solver solver(solver_context);

  KeyInfo lpm_key_info{
      .id = 1,
      .name = "lpm32",
      .type = ParseTextProtoOrDie<Type>("lpm { bitwidth: 32 }"),
  };

  ASSERT_OK_AND_ASSIGN(SymbolicKey key, AddSymbolicKey(lpm_key_info, solver));
  ASSERT_OK_AND_ASSIGN(z3::expr prefix_length, GetPrefixLength(key));
  solver.add(prefix_length == 6);
  EXPECT_EQ(solver.check(), z3::sat);
}

TEST(AddSymbolicKeySensibleConstraintsTest,
     LpmCantHavePrefixLengthAboveBitwidth) {
  z3::context solver_context;
  z3::solver solver(solver_context);

  KeyInfo lpm_key_info{
      .id = 1,
      .name = "lpm32",
      .type = ParseTextProtoOrDie<Type>("lpm { bitwidth: 32 }"),
  };

  ASSERT_OK_AND_ASSIGN(SymbolicKey key, AddSymbolicKey(lpm_key_info, solver));
  ASSERT_OK_AND_ASSIGN(z3::expr prefix_length, GetPrefixLength(key));
  solver.add(prefix_length == 50);
  EXPECT_EQ(solver.check(), z3::unsat);
}

TEST(AddSymbolicKeySensibleConstraintsTest,
     LpmCantHaveValueNotIncludedWithinPrefixLength) {
  z3::context solver_context;
  z3::solver solver(solver_context);

  KeyInfo lpm_key_info{
      .id = 1,
      .name = "lpm32",
      .type = ParseTextProtoOrDie<Type>("lpm { bitwidth: 32 }"),
  };

  ASSERT_OK_AND_ASSIGN(SymbolicKey key, AddSymbolicKey(lpm_key_info, solver));
  ASSERT_OK_AND_ASSIGN(z3::expr value, GetValue(key));
  ASSERT_OK_AND_ASSIGN(z3::expr prefix_length, GetPrefixLength(key));
  solver.add(prefix_length == 2);
  solver.add(value == 0xF00F00);
  EXPECT_EQ(solver.check(), z3::unsat);
}

TEST(AddSymbolicPriorityTest, IsSatisfiable) {
  z3::context solver_context;
  z3::solver solver(solver_context);

  AddSymbolicPriority(solver);
  EXPECT_EQ(solver.check(), z3::sat);
}

TEST(AddSymbolicPriorityTest, ZeroIsUnsat) {
  z3::context solver_context;
  z3::solver solver(solver_context);

  SymbolicAttribute priority_key = AddSymbolicPriority(solver);
  solver.add(priority_key.value == 0);
  EXPECT_EQ(solver.check(), z3::unsat);
}

TEST(AddSymbolicPriorityTest, Positive32BitIntegerIsSat) {
  z3::context solver_context;
  z3::solver solver(solver_context);

  SymbolicAttribute priority_key = AddSymbolicPriority(solver);
  solver.add(priority_key.value == 42);
  EXPECT_EQ(solver.check(), z3::sat);
}

TEST(AddSymbolicPriorityTest, PositiveTooLargeIntegerIsUnsat) {
  z3::context solver_context;
  z3::solver solver(solver_context);

  SymbolicAttribute priority_key = AddSymbolicPriority(solver);
  z3::expr too_large_value = solver_context.int_val(0xFFF'FFFF'FFFF'FFFF);
  solver.add(priority_key.value > too_large_value);
  EXPECT_EQ(solver.check(), z3::unsat);
}

TableInfo GetTableInfoWithConstraint(absl::string_view constraint_string) {
  const Type kExact32 = ParseTextProtoOrDie<Type>("exact { bitwidth: 32 }");
  const Type kTernary32 = ParseTextProtoOrDie<Type>("ternary { bitwidth: 32 }");
  const Type kLpm32 = ParseTextProtoOrDie<Type>("lpm { bitwidth: 32 }");
  const Type kOptional32 =
      ParseTextProtoOrDie<Type>("optional_match { bitwidth: 32 }");
  // Keys whose bitwidth is not a multiple of 8 may be handled somewhat
  // differently, so they are good to test.
  const Type kExact11 = ParseTextProtoOrDie<Type>("exact { bitwidth: 11 }");
  const Type kOptional28 =
      ParseTextProtoOrDie<Type>("optional_match { bitwidth: 28 }");
  const std::string kTableName = "table";

  ConstraintSource source{
      .constraint_string = std::string(constraint_string),
      .constraint_location = ast::SourceLocation(),
  };
  source.constraint_location.set_table_name(kTableName);

  TableInfo table_info{
      .id = 1,
      .name = kTableName,
      .constraint_source = std::move(source),
      .keys_by_id =
          {
              {1, {1, "exact32", kExact32}},
              {2, {2, "ternary32", kTernary32}},
              {3, {3, "lpm32", kLpm32}},
              {4, {4, "optional32", kOptional32}},
              {5, {5, "exact11", kExact11}},
              {6, {6, "optional28", kOptional28}},
          },
      .keys_by_name =
          {
              {"exact32", {1, "exact32", kExact32}},
              {"ternary32", {2, "ternary32", kTernary32}},
              {"lpm32", {3, "lpm32", kLpm32}},
              {"optional32", {4, "optional32", kOptional32}},
              {"exact11", {5, "exact11", kExact11}},
              {"optional28", {6, "optional28", kOptional28}},
          },
  };

  auto constraint = ParseConstraint(ConstraintKind::kTableConstraint,
                                    table_info.constraint_source);
  CHECK_OK(constraint);
  CHECK_OK(InferAndCheckTypes(&(*constraint), table_info));
  table_info.constraint = *constraint;

  // Constraint type must be boolean to not fail early.
  // constraint.mutable_type()->mutable_boolean();
  return table_info;
}

TEST(EvaluateConstraintSymbolicallyTest, SanityCheckAllKeysAreValid) {
  z3::context solver_context;
  z3::solver solver(solver_context);

  TableInfo table_info = GetTableInfoWithConstraint("true");

  for (const auto& [name, key] : table_info.keys_by_name) {
    ASSERT_OK(AddSymbolicKey(key, solver));
  }

  EXPECT_EQ(solver.check(), z3::sat);
}

TEST(EvaluateConstraintSymbolicallyTest,
     NonBooleanConstraintGivesInvalidArgument) {
  z3::context solver_context;
  z3::solver solver(solver_context);

  TableInfo table_info = GetTableInfoWithConstraint("true");
  table_info.constraint->clear_type();

  for (const auto& [name, key] : table_info.keys_by_name) {
    ASSERT_OK(AddSymbolicKey(key, solver));
  }
  EXPECT_THAT(EvaluateConstraintSymbolically(*table_info.constraint,
                                             table_info.constraint_source,
                                             /*environment=*/{}, solver),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

struct ConstraintTestCase {
  std::string test_name;
  // A protobuf string representing an boolean AST Expression representing a
  // constraint.
  std::string constraint_string;
  bool is_sat;
};

using ConstraintTest = testing::TestWithParam<ConstraintTestCase>;

TEST_P(ConstraintTest,
       EvaluateConstraintSymbolicallyCheckSatAndUnsatCorrectness) {
  z3::context solver_context;
  z3::solver solver(solver_context);

  TableInfo table_info =
      GetTableInfoWithConstraint(GetParam().constraint_string);

  // Add symbolic table keys to symbolic key map.
  SymbolicEnvironment environment;
  for (const auto& [key_name, key_info] : table_info.keys_by_name) {
    ASSERT_OK_AND_ASSIGN(SymbolicKey key, AddSymbolicKey(key_info, solver));
    environment.symbolic_key_by_name.insert({key_name, std::move(key)});
  }

  // Add symbolic priority to attribute map.
  SymbolicAttribute symbolic_priority = AddSymbolicPriority(solver);
  environment.symbolic_attribute_by_name.insert(
      {kSymbolicPriorityAttributeName, std::move(symbolic_priority)});

  ASSERT_OK_AND_ASSIGN(z3::expr z3_constraint,
                       EvaluateConstraintSymbolically(
                           *table_info.constraint, table_info.constraint_source,
                           environment, solver));
  solver.add(z3_constraint);
  EXPECT_EQ(solver.check(), GetParam().is_sat ? z3::sat : z3::unsat);
}

TEST(CreateConstraintSolver, WorksWithoutConstraints) {
  TableInfo table_info = GetTableInfoWithConstraint("true");
  table_info.constraint = std::nullopt;

  EXPECT_OK(ConstraintSolver::Create(table_info));
}

TEST(CreateConstraintSolverAddConstraint, WorksWithoutPriority) {
  TableInfo table_info = GetTableInfoWithConstraint("true");

  // Remove the ternaries and optionals, so that no priority is required.
  std::vector<KeyInfo> keys_to_remove;
  for (const auto& [key_name, key_info] : table_info.keys_by_name) {
    if (key_info.type.has_ternary() || key_info.type.has_optional_match()) {
      keys_to_remove.push_back(key_info);
    }
  }
  for (const KeyInfo& key : keys_to_remove) {
    table_info.keys_by_name.erase(key.name);
    table_info.keys_by_id.erase(key.id);
  }
  EXPECT_OK(ConstraintSolver::Create(table_info));
}

TEST_P(ConstraintTest, CreateOnlyWorksWithSatisfiableConstraints) {
  TableInfo table_info =
      GetTableInfoWithConstraint(GetParam().constraint_string);

  EXPECT_THAT(
      ConstraintSolver::Create(table_info),
      (GetParam().is_sat ? StatusIs(absl::StatusCode::kOk)
                         : StatusIs(absl::StatusCode::kInvalidArgument)));
}

TEST_P(ConstraintTest, CreateConstraintSolverAndConcretizeEntry) {
  if (!GetParam().is_sat) {
    GTEST_SKIP() << "Test only sensible for satisfiable constraints";
  }
  TableInfo table_info =
      GetTableInfoWithConstraint(GetParam().constraint_string);

  ASSERT_OK_AND_ASSIGN(ConstraintSolver constraint_solver,
                       ConstraintSolver::Create(table_info));

  ASSERT_OK_AND_ASSIGN(p4::v1::TableEntry concretized_entry,
                       constraint_solver.ConcretizeEntry());

  // The empty string signifies that the entry doesn't violate the constraint.
  ConstraintInfo context{
      .action_info_by_id = {},
      .table_info_by_id = {{
          table_info.id,
          table_info,
      }},
  };
  EXPECT_THAT(ReasonEntryViolatesConstraint(concretized_entry, context),
              IsOkAndHolds(""))
      << "\nFor entry:\n"
      << concretized_entry.DebugString()
      << "\nConstraint string: " << GetParam().constraint_string
      << "\nConstraint: " << table_info.constraint->DebugString();
}

INSTANTIATE_TEST_SUITE_P(
    EvaluateConstraintSatisfiabilityTests, ConstraintTest,
    testing::ValuesIn(std::vector<ConstraintTestCase>{
        {
            .test_name = "true_is_sat",
            .constraint_string = "true",
            .is_sat = true,
        },
        {
            .test_name = "false_is_unsat",
            .constraint_string = "false",
            .is_sat = false,
        },
        {
            .test_name = "boolean_negation",
            .constraint_string = "!false",
            .is_sat = true,
        },
        {
            .test_name = "integer_equality_sat",
            .constraint_string = "42 == 42",
            .is_sat = true,
        },
        {
            .test_name = "integer_negation_unsat",
            .constraint_string = "-42 > 12398712983",
            .is_sat = false,
        },
        {
            .test_name = "exact_with_type_casts",
            .constraint_string = "exact32 == 42",
            .is_sat = true,
        },
        {
            .test_name = "lpm_prefix_length_field_access_unsat",
            .constraint_string = "lpm32::prefix_length < -1",
            .is_sat = false,
        },
        {
            .test_name = "value_field_accesses",
            .constraint_string = "exact32::value == ternary32::value",
            .is_sat = true,
        },
        {
            .test_name = "optional_mask_field_access_sat",
            .constraint_string = "optional32::mask == 0",
            .is_sat = true,
        },
        {
            .test_name = "optional_mask_field_access_unsat",
            .constraint_string = "optional32::mask == 50",
            .is_sat = false,
        },
        {
            .test_name = "optional_equals_sat",
            .constraint_string = "optional32 == 1",
            .is_sat = true,
        },
        {
            .test_name = "ternary_equals_sat",
            .constraint_string = "ternary32 == 42",
            .is_sat = true,
        },
        {
            .test_name = "lpm_not_equals_sat",
            .constraint_string = "lpm32 != 42",
            .is_sat = true,
        },
        {
            .test_name = "priority_unsat",
            .constraint_string = "::priority < 1",
            .is_sat = false,
        },
        {
            .test_name = "priority_sat",
            .constraint_string = "::priority > 50",
            .is_sat = true,
        },
        {
            .test_name = "exact_may_have_odd_bitwidth",
            .constraint_string = "exact11 == 137",
            .is_sat = true,
        },
        {
            .test_name = "lpm_can_have_zero_prefix",
            .constraint_string = "lpm32::prefix_length == 0",
            .is_sat = true,
        },
        {
            .test_name = "optional28_equals_sat",
            .constraint_string = "optional28 == 1",
            .is_sat = true,
        },
    }),
    [](const testing::TestParamInfo<ConstraintTestCase>& info) {
      return SnakeCaseToCamelCase(info.param.test_name);
    });

struct FullySpecifiedConstraintTestCase {
  std::string test_name;
  // A protobuf string representing an boolean AST Expression representing a
  // constraint. Must fully specify the entry given below.
  std::string constraint_string;
  // Should be set with the only entry that can possibly meet the constraint
  // string.
  p4::v1::TableEntry expected_concretized_entry;
  // Optionally, specify a set of keys that should be skipped when concretizing
  // the table entry. This only makes sense for non-required keys.
  absl::flat_hash_set<std::string> keys_to_skip;
};

using FullySpecifiedConstraintTest =
    testing::TestWithParam<FullySpecifiedConstraintTestCase>;

TEST_P(FullySpecifiedConstraintTest,
       CreateConstraintSolverAndConcretizeEntryGivesExactEntry) {
  TableInfo table_info =
      GetTableInfoWithConstraint(GetParam().constraint_string);
  ConstraintInfo context{
      .action_info_by_id = {},
      .table_info_by_id = {{
          table_info.id,
          table_info,
      }},
  };

  // Sanity check that the expected entry actually satisfies the constraint.
  // The empty string signifies that the entry doesn't violate the constraint.
  ASSERT_THAT(ReasonEntryViolatesConstraint(
                  GetParam().expected_concretized_entry, context),
              IsOkAndHolds(""))
      << "\nFor entry:\n"
      << GetParam().expected_concretized_entry.DebugString()
      << "\nConstraint string: " << GetParam().constraint_string
      << "\nConstraint: " << table_info.constraint->DebugString();

  ASSERT_OK_AND_ASSIGN(
      ConstraintSolver constraint_solver,
      ConstraintSolver::Create(table_info, [&](absl::string_view key_name) {
        return GetParam().keys_to_skip.contains(key_name);
      }));

  ASSERT_OK_AND_ASSIGN(p4::v1::TableEntry concretized_entry,
                       constraint_solver.ConcretizeEntry());

  EXPECT_THAT(concretized_entry, IgnoringRepeatedFieldOrdering(EqualsProto(
                                     GetParam().expected_concretized_entry)));
}

INSTANTIATE_TEST_SUITE_P(
    CheckExactEntryOutput, FullySpecifiedConstraintTest,
    testing::ValuesIn(std::vector<FullySpecifiedConstraintTestCase>{
        {
            .test_name = "only_equals",
            .constraint_string =
                "exact11 == 5; exact32 == 5; ::priority == 50; "
                "lpm32::prefix_length == 0; ternary32::mask == 0; "
                "optional32::mask == 0; optional28::mask == 0;",
            .expected_concretized_entry =
                ParseTextProtoOrDie<p4::v1::TableEntry>(R"pb(
                  table_id: 1
                  match {
                    field_id: 1
                    exact { value: "\005" }
                  }
                  match {
                    field_id: 5
                    exact { value: "\005" }
                  }
                  priority: 50
                )pb"),
        },
        {
            .test_name = "last_byte_zero_in_exacts",
            .constraint_string =
                "exact11 == 1280; exact32 == 1280; ::priority == 50; "
                "lpm32::prefix_length == 0; ternary32::mask == 0; "
                "optional32::mask == 0; optional28::mask == 0;",
            .expected_concretized_entry =
                ParseTextProtoOrDie<p4::v1::TableEntry>(R"pb(
                  table_id: 1
                  match {
                    field_id: 1
                    exact { value: "\005\000" }
                  }
                  match {
                    field_id: 5
                    exact { value: "\005\000" }
                  }
                  priority: 50
                )pb"),
        },
        {
            .test_name = "with_inequalities",
            .constraint_string = "::priority > 1; ::priority < 3; "
                                 "lpm32::prefix_length == 0; ternary32::mask "
                                 "== 0; optional32::mask == 0; exact11 == 1; "
                                 "exact32 == 1; optional28::mask == 0;",
            .expected_concretized_entry =
                ParseTextProtoOrDie<p4::v1::TableEntry>(R"pb(
                  table_id: 1
                  match {
                    field_id: 1
                    exact { value: "\001" }
                  }
                  match {
                    field_id: 5
                    exact { value: "\001" }
                  }
                  priority: 2
                )pb"),
        },
        {
            .test_name = "set_lpm",
            .constraint_string = "lpm32 == 5; "
                                 "ternary32::mask == 0; optional32::mask == 0; "
                                 "exact11 == 1; exact32 == 1; ::priority == 1; "
                                 "optional28::mask == 0;",
            .expected_concretized_entry =
                ParseTextProtoOrDie<p4::v1::TableEntry>(R"pb(
                  table_id: 1
                  match {
                    field_id: 1
                    exact { value: "\001" }
                  }
                  match {
                    field_id: 3
                    lpm { value: "\005" prefix_len: 32 }
                  }
                  match {
                    field_id: 5
                    exact { value: "\001" }
                  }
                  priority: 1
                )pb"),
        },
        {
            .test_name = "set_ternary",
            .constraint_string =
                "ternary32 == 5; "
                "lpm32::prefix_length == 0; optional32::mask == 0; exact11 == "
                "1; exact32 == 1; ::priority == 1; optional28::mask == 0;",
            .expected_concretized_entry =
                ParseTextProtoOrDie<p4::v1::TableEntry>(R"pb(
                  table_id: 1
                  match {
                    field_id: 1
                    exact { value: "\001" }
                  }
                  match {
                    field_id: 2
                    ternary { value: "\005" mask: "\377\377\377\377" }
                  }
                  match {
                    field_id: 5
                    exact { value: "\001" }
                  }
                  priority: 1
                )pb"),
        },
        {
            .test_name = "set_optional32",
            .constraint_string =
                "optional32 == 5; "
                "lpm32::prefix_length == 0; ternary32::mask == 0;  exact11 == "
                "1; exact32 == 1; ::priority == 1; optional28::mask == 0;",
            .expected_concretized_entry =
                ParseTextProtoOrDie<p4::v1::TableEntry>(R"pb(
                  table_id: 1
                  match {
                    field_id: 1
                    exact { value: "\001" }
                  }
                  match {
                    field_id: 4
                    optional { value: "\005" }
                  }
                  match {
                    field_id: 5
                    exact { value: "\001" }
                  }
                  priority: 1
                )pb"),
        },
        {
            .test_name = "set_optional28",
            .constraint_string =
                "optional28 == 5; "
                "lpm32::prefix_length == 0; ternary32::mask == 0; exact11 == "
                "1; exact32 == 1; ::priority == 1; optional32::mask == 0;",
            .expected_concretized_entry =
                ParseTextProtoOrDie<p4::v1::TableEntry>(R"pb(
                  table_id: 1
                  match {
                    field_id: 1
                    exact { value: "\001" }
                  }
                  match {
                    field_id: 5
                    exact { value: "\001" }
                  }
                  match {
                    field_id: 6
                    optional { value: "\005" }
                  }
                  priority: 1
                )pb"),
        },
        {
            .test_name = "skip_optionals",
            .constraint_string =
                "lpm32::prefix_length == 0; ternary32::mask == 0; exact11 == 1;"
                "exact32 == 1; ::priority == 1;",
            .expected_concretized_entry =
                ParseTextProtoOrDie<p4::v1::TableEntry>(R"pb(
                  table_id: 1
                  match {
                    field_id: 1
                    exact { value: "\001" }
                  }
                  match {
                    field_id: 5
                    exact { value: "\001" }
                  }
                  priority: 1
                )pb"),
            .keys_to_skip = {"optional32", "optional28"},
        },
    }),
    [](const testing::TestParamInfo<FullySpecifiedConstraintTestCase>& info) {
      return SnakeCaseToCamelCase(info.param.test_name);
    });

TEST(AddConstraint, NonBooleanConstraintGivesInvalidArgument) {
  ASSERT_OK_AND_ASSIGN(
      ConstraintSolver constraint_solver,
      ConstraintSolver::Create(GetTableInfoWithConstraint("true")));

  EXPECT_THAT(constraint_solver.AddConstraint("42"),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AddConstraint, UnknownVariableGivesInvalidArgument) {
  ASSERT_OK_AND_ASSIGN(
      ConstraintSolver constraint_solver,
      ConstraintSolver::Create(GetTableInfoWithConstraint("true")));

  EXPECT_THAT(constraint_solver.AddConstraint("dragon == 42"),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AddConstraint, OnlySatisfiableConstraintCanBeAdded) {
  ASSERT_OK_AND_ASSIGN(
      ConstraintSolver constraint_solver,
      ConstraintSolver::Create(GetTableInfoWithConstraint("true")));

  EXPECT_THAT(constraint_solver.AddConstraint("false"), IsOkAndHolds(false));

  EXPECT_THAT(constraint_solver.AddConstraint("true"), IsOkAndHolds(true));
}

struct AdditionalConstraintTestCase {
  std::string test_name;
  // A protobuf string representing a boolean AST Expression representing a
  // constraint.
  std::string p4_program_constraint_string;
  std::string custom_constraint_string;
  bool is_sat;
};

using AdditionalConstraintTest =
    testing::TestWithParam<AdditionalConstraintTestCase>;

TEST_P(AdditionalConstraintTest,
       AddConstraintOnlyAddsSatisfiableConstraintsToSolver) {
  TableInfo table_info =
      GetTableInfoWithConstraint(GetParam().p4_program_constraint_string);

  ASSERT_OK_AND_ASSIGN(ConstraintSolver constraint_solver,
                       ConstraintSolver::Create(table_info));

  EXPECT_THAT(
      constraint_solver.AddConstraint(GetParam().custom_constraint_string),
      IsOkAndHolds(GetParam().is_sat));
}

TEST_P(AdditionalConstraintTest, AddConstraintAndConcretizeEntry) {
  if (!GetParam().is_sat) {
    GTEST_SKIP() << "Test only sensible for satisfiable constraints";
  }

  TableInfo table_info =
      GetTableInfoWithConstraint(GetParam().p4_program_constraint_string);

  ASSERT_OK_AND_ASSIGN(ConstraintSolver constraint_solver,
                       ConstraintSolver::Create(table_info));

  ASSERT_THAT(
      constraint_solver.AddConstraint(GetParam().custom_constraint_string),
      IsOkAndHolds(true));

  ASSERT_OK_AND_ASSIGN(p4::v1::TableEntry concretized_entry,
                       constraint_solver.ConcretizeEntry());

  // The empty string signifies that the entry doesn't violate the
  ConstraintInfo context{
      .action_info_by_id = {},
      .table_info_by_id = {{
          table_info.id,
          table_info,
      }},
  };
  EXPECT_THAT(ReasonEntryViolatesConstraint(concretized_entry, context),
              IsOkAndHolds(""))
      << "\nFor entry:\n"
      << concretized_entry.DebugString() << "\nP4 program constraint string: "
      << "\nP4 program constraint: " << table_info.constraint->DebugString()
      << GetParam().p4_program_constraint_string
      << "\nCustom constraint string: " << GetParam().custom_constraint_string;
}

INSTANTIATE_TEST_SUITE_P(
    AddtionalConstraintSatisfiabilityTests, AdditionalConstraintTest,
    testing::ValuesIn(std::vector<AdditionalConstraintTestCase>{
        {
            .test_name = "adding_sat_does_not_affect_sat",
            .p4_program_constraint_string = "true",
            .custom_constraint_string = "true",
            .is_sat = true,
        },
        {
            .test_name = "adding_unsat_forces_unsat",
            .p4_program_constraint_string = "true",
            .custom_constraint_string = "false",
            .is_sat = false,
        },
        {
            .test_name = "independent_sats_are_sat",
            .p4_program_constraint_string = "exact32 == 42;",
            .custom_constraint_string = "optional32 != 42",
            .is_sat = true,
        },
        {
            .test_name = "related_and_compatible_sats_are_sat",
            .p4_program_constraint_string = "exact32 == 42;",
            .custom_constraint_string = "exact32 != 7",
            .is_sat = true,
        },
        {
            .test_name = "related_and_conflicting_sats_are_unsat",
            .p4_program_constraint_string = "exact32 == 42;",
            .custom_constraint_string = "exact32 != 42",
            .is_sat = false,
        },
    }),
    [](const testing::TestParamInfo<AdditionalConstraintTestCase>& info) {
      return SnakeCaseToCamelCase(info.param.test_name);
    });

struct FullySpecifiedAdditionalConstraintTestCase {
  std::string test_name;
  // Protobuf strings representing a boolean AST Expression coming from a p4
  // program and additional custom constraint respectively. The combination of
  // both must fully specify the entry given below.
  std::string p4_info_constraint_string;
  std::string custom_constraint_string;
  // Should be set with the only entry that can possibly meet the combination
  // of constraint strings.
  p4::v1::TableEntry expected_concretized_entry;
  // Optionally, specify a set of keys that should be skipped when
  // concretizing the table entry. This only makes sense for non-required keys.
  absl::flat_hash_set<std::string> keys_to_skip;
};

using FullySpecifiedAdditionalConstraintTest =
    testing::TestWithParam<FullySpecifiedAdditionalConstraintTestCase>;

TEST_P(FullySpecifiedAdditionalConstraintTest,
       EncodeValidTableEntryAndConcretizeEntryGivesExactEntry) {
  TableInfo table_info =
      GetTableInfoWithConstraint(GetParam().p4_info_constraint_string);
  ConstraintInfo context{
      .action_info_by_id = {},
      .table_info_by_id = {{
          table_info.id,
          table_info,
      }},
  };

  // Sanity check that the expected entry actually satisfies the constraint.
  // The empty string signifies that the entry doesn't violate the
  ASSERT_THAT(ReasonEntryViolatesConstraint(
                  GetParam().expected_concretized_entry, context),
              IsOkAndHolds(""))
      << "\nFor entry:\n"
      << GetParam().expected_concretized_entry.DebugString()
      << "\nConstraint string: " << GetParam().p4_info_constraint_string
      << "\nConstraint: " << table_info.constraint->DebugString();

  ASSERT_OK_AND_ASSIGN(ConstraintSolver constraint_solver,
                       ConstraintSolver::Create(table_info));

  ASSERT_THAT(
      constraint_solver.AddConstraint(GetParam().custom_constraint_string),
      IsOkAndHolds(true));

  ASSERT_OK_AND_ASSIGN(p4::v1::TableEntry concretized_entry,
                       constraint_solver.ConcretizeEntry());

  EXPECT_THAT(concretized_entry, IgnoringRepeatedFieldOrdering(EqualsProto(
                                     GetParam().expected_concretized_entry)));
}

INSTANTIATE_TEST_SUITE_P(
    CheckExactEntryOutput, FullySpecifiedAdditionalConstraintTest,
    testing::ValuesIn(std::vector<FullySpecifiedAdditionalConstraintTestCase>{
        {
            .test_name = "only_equals_across_both_constraints",
            .p4_info_constraint_string =
                "exact11 == 5; ::priority == 50; "
                "optional32::mask == 0; optional28::mask == 0;",
            .custom_constraint_string =
                "exact32 == 5; "
                "lpm32::prefix_length == 0; ternary32::mask == 0; ",
            .expected_concretized_entry =
                ParseTextProtoOrDie<p4::v1::TableEntry>(R"pb(
                  table_id: 1
                  match {
                    field_id: 1
                    exact { value: "\005" }
                  }
                  match {
                    field_id: 5
                    exact { value: "\005" }
                  }
                  priority: 50
                )pb"),
        },
        {
            .test_name = "exact_inequalities_across_both_constraints",
            .p4_info_constraint_string =
                "::priority > 1; exact32::value > 1; exact11::value > 1;"
                "lpm32::prefix_length == 0; ternary32::mask == 0;"
                " optional32::mask == 0;  optional28::mask == 0;",
            .custom_constraint_string =
                "::priority < 3; exact32::value < 3; exact11::value < 3;",
            .expected_concretized_entry =
                ParseTextProtoOrDie<p4::v1::TableEntry>(R"pb(
                  table_id: 1
                  match {
                    field_id: 1
                    exact { value: "\002" }
                  }
                  match {
                    field_id: 5
                    exact { value: "\002" }
                  }
                  priority: 2
                )pb"),
        },
    }),
    [](const testing::TestParamInfo<FullySpecifiedAdditionalConstraintTestCase>&
           info) { return SnakeCaseToCamelCase(info.param.test_name); });

}  // namespace
}  // namespace p4_constraints
