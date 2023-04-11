#include "p4_constraints/backend/symbolic_interpreter.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "gutils/parse_text_proto.h"
#include "gutils/status_matchers.h"
#include "gutils/testing.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/backend/constraint_info.h"
#include "z3++.h"

namespace p4_constraints {
namespace {

using ::gutils::ParseTextProtoOrDie;
using ::gutils::SnakeCaseToCamelCase;
using ::gutils::testing::status::IsOk;
using ::gutils::testing::status::StatusIs;
using ::p4_constraints::ast::Expression;
using ::p4_constraints::ast::Type;
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

  return TableInfo{
      .id = 1,
      .name = "table",
      .constraint = ParseTextProtoOrDie<Expression>(constraint_string),
      .keys_by_name = {
          {"exact32", {1, "exact32", kExact32}},
          {"ternary32", {2, "ternary32", kTernary32}},
          {"lpm32", {3, "lpm32", kLpm32}},
          {"optional32", {4, "optional32", kOptional32}},
      }};
}

TEST(EvaluateConstraintSymbolicallyTest, SanityCheckAllKeysAreValid) {
  z3::context solver_context;
  z3::solver solver(solver_context);

  TableInfo table_info = GetTableInfoWithConstraint("");

  for (const auto& [name, key] : table_info.keys_by_name) {
    ASSERT_OK(AddSymbolicKey(key, solver));
  }

  EXPECT_EQ(solver.check(), z3::sat);
}

TEST(EvaluateConstraintSymbolicallyTest,
     NonBooleanConstraintGivesInvalidArgument) {
  z3::context solver_context;
  z3::solver solver(solver_context);

  TableInfo table_info = GetTableInfoWithConstraint("");
  table_info.constraint->clear_type();

  for (const auto& [name, key] : table_info.keys_by_name) {
    ASSERT_OK(AddSymbolicKey(key, solver));
  }
  EXPECT_THAT(EvaluateConstraintSymbolically(
                  *table_info.constraint, table_info.constraint_source,
                  /*name_to_symbolic_key=*/{},
                  /*name_to_symbolic_attribute=*/{}, solver),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

struct EvaluateConstraintTestCase {
  std::string test_name;
  // A protobuf string representing an boolean AST Expression representing a
  // constraint.
  std::string constraint_string;
  bool is_sat;
};

using EvaluateConstraintSymbolicallyTest =
    testing::TestWithParam<EvaluateConstraintTestCase>;

TEST_P(EvaluateConstraintSymbolicallyTest, CheckSatAndUnsatCorrectness) {
  z3::context solver_context;
  z3::solver solver(solver_context);

  TableInfo table_info =
      GetTableInfoWithConstraint(GetParam().constraint_string);
  // Constraint type must be boolean to not fail early.
  table_info.constraint->mutable_type()->mutable_boolean();

  // Add symbolic table keys to symbolic key map.
  absl::flat_hash_map<std::string, SymbolicKey> name_to_symbolic_key;
  for (const auto& [key_name, key_info] : table_info.keys_by_name) {
    ASSERT_OK_AND_ASSIGN(SymbolicKey key, AddSymbolicKey(key_info, solver));
    name_to_symbolic_key.emplace(key_name, std::move(key));
  }

  // Add symbolic priority to attribute map.
  absl::flat_hash_map<std::string, SymbolicAttribute>
      name_to_symbolic_attribute;
  SymbolicAttribute symbolic_priority = AddSymbolicPriority(solver);
  name_to_symbolic_attribute.emplace("priority", std::move(symbolic_priority));

  ASSERT_OK_AND_ASSIGN(
      z3::expr z3_constraint,
      EvaluateConstraintSymbolically(
          *table_info.constraint, table_info.constraint_source,
          name_to_symbolic_key, name_to_symbolic_attribute, solver));
  solver.add(z3_constraint);
  EXPECT_EQ(solver.check(), GetParam().is_sat ? z3::sat : z3::unsat);
}

INSTANTIATE_TEST_SUITE_P(
    EvaluateConstraintSatisfiabilityTests, EvaluateConstraintSymbolicallyTest,
    testing::ValuesIn(std::vector<EvaluateConstraintTestCase>{
        {
            .test_name = "true_is_sat",
            .constraint_string = "boolean_constant: true",
            .is_sat = true,
        },
        {
            .test_name = "false_is_unsat",
            .constraint_string = "boolean_constant: false",
            .is_sat = false,
        },
        {
            .test_name = "boolean_negation",
            .constraint_string = "boolean_negation {boolean_constant: false }",
            .is_sat = true,
        },
        {
            .test_name = "integer_equality_sat",
            .constraint_string = R"pb(
              binary_expression {
                binop: EQ
                left { integer_constant: "42" }
                right { integer_constant: "42" }
              }
            )pb",
            .is_sat = true,
        },
        {
            .test_name = "integer_negation_unsat",
            .constraint_string = R"pb(
              binary_expression {
                binop: GT
                left { arithmetic_negation: { integer_constant: "42" } }
                right { integer_constant: "1928371273691273631927631927" }
              }
            )pb",
            .is_sat = false,
        },
        {
            .test_name = "exact_with_type_casts",
            .constraint_string = R"pb(
              binary_expression {
                binop: EQ
                left {
                  type { exact { bitwidth: 32 } }
                  key: "exact32"
                }
                right {
                  type { exact { bitwidth: 32 } }
                  type_cast {
                    type { fixed_unsigned { bitwidth: 32 } }
                    type_cast {
                      type { arbitrary_int {} }
                      integer_constant: "42"
                    }
                  }
                }
              }
            )pb",
            .is_sat = true,
        },
        {
            .test_name = "lpm_prefix_length_field_access_sat",
            .constraint_string = R"pb(
              binary_expression {
                binop: NE
                left {
                  type { arbitrary_int {} }
                  field_access {
                    field: "prefix_length"
                    expr {
                      type { lpm { bitwidth: 32 } }
                      key: "lpm32"
                    }
                  }
                }
                right { integer_constant: "10" }
              }
            )pb",
            .is_sat = true,
        },
        {
            .test_name = "lpm_prefix_length_field_access_unsat",
            .constraint_string = R"pb(
              binary_expression {
                binop: LT
                left {
                  type { arbitrary_int {} }
                  field_access {
                    field: "prefix_length"
                    expr {
                      type { lpm { bitwidth: 32 } }
                      key: "lpm32"
                    }
                  }
                }
                right { integer_constant: "-1" }
              }
            )pb",
            .is_sat = false,
        },
        {
            .test_name = "value_field_accesses",
            .constraint_string = R"pb(
              binary_expression {
                binop: EQ
                left {
                  type { exact { bitwidth: 32 } }
                  field_access {
                    field: "value"
                    expr {
                      type { exact { bitwidth: 32 } }
                      key: "exact32"
                    }
                  }
                }
                right {
                  type { ternary { bitwidth: 32 } }
                  field_access {
                    field: "value"
                    expr {
                      type { exact { bitwidth: 32 } }
                      key: "ternary32"
                    }
                  }
                }
              }
            )pb",
            .is_sat = true,
        },
        {
            .test_name = "optional_mask_field_access_sat",
            .constraint_string = R"pb(
              binary_expression {
                binop: EQ
                left {
                  type { fixed_unsigned { bitwidth: 32 } }
                  field_access {
                    field: "mask"
                    expr {
                      type { optional_match { bitwidth: 32 } }
                      key: "optional32"
                    }
                  }
                }
                right {
                  type { fixed_unsigned { bitwidth: 32 } }
                  type_cast {
                    type { arbitrary_int {} }
                    integer_constant: "0"
                  }
                }
              }
            )pb",
            .is_sat = true,
        },
        {
            .test_name = "optional_mask_field_access_unsat",
            .constraint_string = R"pb(
              binary_expression {
                binop: EQ
                left {
                  type { fixed_unsigned { bitwidth: 32 } }
                  field_access {
                    field: "mask"
                    expr {
                      type { optional_match { bitwidth: 32 } }
                      key: "optional32"
                    }
                  }
                }
                right {
                  type { fixed_unsigned { bitwidth: 32 } }
                  type_cast {
                    type { arbitrary_int {} }
                    integer_constant: "50"
                  }
                }
              }
            )pb",
            .is_sat = false,
        },
        {
            .test_name = "optional_equals_sat",
            .constraint_string = R"pb(
              binary_expression {
                binop: EQ
                left {
                  type { optional_match { bitwidth: 32 } }
                  key: "optional32"
                }
                right {
                  type { optional_match { bitwidth: 32 } }
                  type_cast {
                    type { fixed_unsigned { bitwidth: 32 } }
                    type_cast {
                      type { arbitrary_int {} }
                      integer_constant: "42"
                    }
                  }
                }
              }
            )pb",
            .is_sat = true,
        },
        {
            .test_name = "ternary_equals_sat",
            .constraint_string = R"pb(
              binary_expression {
                binop: EQ
                left {
                  type { ternary { bitwidth: 32 } }
                  key: "ternary32"
                }
                right {
                  type { ternary { bitwidth: 32 } }
                  type_cast {
                    type { fixed_unsigned { bitwidth: 32 } }
                    type_cast {
                      type { arbitrary_int {} }
                      integer_constant: "42"
                    }
                  }
                }
              }
            )pb",
            .is_sat = true,
        },
        {
            .test_name = "lpm_not_equals_sat",
            .constraint_string = R"pb(
              binary_expression {
                binop: NE
                left {
                  type { lpm { bitwidth: 32 } }
                  key: "lpm32"
                }
                right {
                  type { lpm { bitwidth: 32 } }
                  type_cast {
                    type { fixed_unsigned { bitwidth: 32 } }
                    type_cast {
                      type { arbitrary_int {} }
                      integer_constant: "42"
                    }
                  }
                }
              }
            )pb",
            .is_sat = true,
        },
        {
            .test_name = "priority_unsat",
            .constraint_string = R"pb(
              binary_expression {
                binop: LT
                left { attribute_access { attribute_name: "priority" } }
                right { integer_constant: "1" }
              }
            )pb",
            .is_sat = false,
        },
        {
            .test_name = "priority_sat",
            .constraint_string = R"pb(
              binary_expression {
                binop: GT
                left { attribute_access { attribute_name: "priority" } }
                right { integer_constant: "50" }
              }
            )pb",
            .is_sat = true,
        },
    }),
    [](const testing::TestParamInfo<EvaluateConstraintTestCase>& info) {
      return SnakeCaseToCamelCase(info.param.test_name);
    });

}  // namespace
}  // namespace p4_constraints
