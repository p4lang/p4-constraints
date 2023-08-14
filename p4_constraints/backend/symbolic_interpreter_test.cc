#include "p4_constraints/backend/symbolic_interpreter.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include "absl/status/status.h"
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

}  // namespace
}  // namespace p4_constraints
