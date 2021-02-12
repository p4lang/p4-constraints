// Copied and adapted from https://github.com/google/iree.

// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef GUTILS_INTERNAL_STATUS_MATCHERS_H_
#define GUTILS_INTERNAL_STATUS_MATCHERS_H_

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/types/optional.h"

#undef EXPECT_OK
#undef ASSERT_OK
#undef ASSERT_OK_AND_ASSIGN

namespace gutils {

namespace internal {

// Implements a gMock matcher that checks that an absl::StaturOr<T> has an OK
// status and that the contained T value matches another matcher.
template <typename T>
class IsOkAndHoldsMatcher
    : public ::testing::MatcherInterface<const absl::StatusOr<T> &> {
 public:
  template <typename MatcherT>
  IsOkAndHoldsMatcher(MatcherT &&value_matcher)
      : value_matcher_(::testing::SafeMatcherCast<const T &>(value_matcher)) {}

  // From testing::MatcherInterface.
  void DescribeTo(std::ostream *os) const override {
    *os << "is OK and contains a value that ";
    value_matcher_.DescribeTo(os);
  }

  // From testing::MatcherInterface.
  void DescribeNegationTo(std::ostream *os) const override {
    *os << "is not OK or contains a value that ";
    value_matcher_.DescribeNegationTo(os);
  }

  // From testing::MatcherInterface.
  bool MatchAndExplain(
      const absl::StatusOr<T> &status_or,
      ::testing::MatchResultListener *listener) const override {
    if (!status_or.ok()) {
      *listener << "which is not OK";
      return false;
    }

    ::testing::StringMatchResultListener value_listener;
    bool is_a_match =
        value_matcher_.MatchAndExplain(status_or.value(), &value_listener);
    std::string value_explanation = value_listener.str();
    if (!value_explanation.empty()) {
      *listener << absl::StrCat("which contains a value ", value_explanation);
    }

    return is_a_match;
  }

 private:
  const ::testing::Matcher<const T &> value_matcher_;
};

// A polymorphic IsOkAndHolds() matcher.
//
// IsOkAndHolds() returns a matcher that can be used to process an IsOkAndHolds
// expectation. However, the value type T is not provided when IsOkAndHolds() is
// invoked. The value type is only inferable when the gUnit framework invokes
// the matcher with a value. Consequently, the IsOkAndHolds() function must
// return an object that is implicitly convertible to a matcher for
// absl::StatusOr<T>. gUnit refers to such an object as a polymorphic matcher,
// since it can be used to match with more than one type of value.
template <typename ValueMatcherT>
class IsOkAndHoldsGenerator {
 public:
  explicit IsOkAndHoldsGenerator(ValueMatcherT value_matcher)
      : value_matcher_(std::move(value_matcher)) {}

  template <typename T>
  operator ::testing::Matcher<const absl::StatusOr<T> &>() const {
    return ::testing::MakeMatcher(new IsOkAndHoldsMatcher<T>(value_matcher_));
  }

 private:
  const ValueMatcherT value_matcher_;
};

// Implements a gMock matcher for checking error-code expectations on
// absl::Status and absl::StatusOr objects.
template <typename Enum, typename Matchee>
class StatusMatcher : public ::testing::MatcherInterface<Matchee> {
 public:
  StatusMatcher(Enum code, absl::optional<absl::string_view> message)
      : code_(code), message_(message) {}

  // From testing::MatcherInterface.
  //
  // Describes the expected error code.
  void DescribeTo(std::ostream *os) const override {
    *os << "error code " << StatusCodeToString(code_);
    if (message_.has_value()) {
      *os << "::'" << message_.value() << "'";
    }
  }

  // From testing::MatcherInterface.
  //
  // Tests whether |matchee| has an error code that meets this matcher's
  // expectation. If an error message string is specified in this matcher, it
  // also tests that |matchee| has an error message that matches that
  // expectation.
  bool MatchAndExplain(
      Matchee &matchee,
      ::testing::MatchResultListener *listener) const override {
    if (GetCode(matchee) != code_) {
      *listener << "whose error code is "
                << StatusCodeToString(GetCode(matchee));
      return false;
    }
    if (message_.has_value() && GetMessage(matchee) != message_.value()) {
      *listener << "whose error message is '" << GetMessage(matchee) << "'";
      return false;
    }
    return true;
  }

 private:
  template <typename T>
  absl::StatusCode GetCode(const T &matchee) const {
    return GetCode(matchee.status());
  }

  absl::StatusCode GetCode(const absl::Status &status) const {
    return status.code();
  }

  template <typename T>
  absl::string_view GetMessage(const T &matchee) const {
    return GetMessage(matchee.status());
  }

  absl::string_view GetMessage(const absl::Status &status) const {
    return status.message();
  }

  // Expected error code.
  const Enum code_;

  // Expected error message (empty if none expected and verified).
  const absl::optional<std::string> message_;
};

// StatusMatcherGenerator is an intermediate object returned by
// gutils::testing::status::StatusIs().
// It implements implicit type-cast operators to supported matcher types:
// Matcher<const absl::Status &> and Matcher<const absl::StatusOr<T> &>. These
// typecast operators create gMock matchers that test OK expectations on a
// status container.
template <typename Enum>
class StatusIsMatcherGenerator {
 public:
  StatusIsMatcherGenerator(Enum code, absl::optional<absl::string_view> message)
      : code_(code), message_(message) {}

  // Type-cast operator for Matcher<const absl::Status &>.
  operator ::testing::Matcher<const absl::Status &>() const {
    return ::testing::MakeMatcher(
        new internal::StatusMatcher<Enum, const absl::Status &>(code_,
                                                                message_));
  }

  // Type-cast operator for Matcher<const absl::StatusOr<T> &>.
  template <class T>
  operator ::testing::Matcher<const absl::StatusOr<T> &>() const {
    return ::testing::MakeMatcher(
        new internal::StatusMatcher<Enum, const absl::StatusOr<T> &>(code_,
                                                                     message_));
  }

 private:
  // Expected error code.
  const Enum code_;

  // Expected error message (empty if none expected and verified).
  const absl::optional<std::string> message_;
};

// Implements a gMock matcher that checks whether a status container (e.g.
// absl::Status or absl::StatusOr<T>) has an OK status.
template <class T>
class IsOkMatcherImpl : public ::testing::MatcherInterface<T> {
 public:
  IsOkMatcherImpl() = default;

  // From testing::MatcherInterface.
  //
  // Describes the OK expectation.
  void DescribeTo(std::ostream *os) const override { *os << "is OK"; }

  // From testing::MatcherInterface.
  //
  // Describes the negative OK expectation.
  void DescribeNegationTo(std::ostream *os) const override {
    *os << "is not OK";
  }

  // From testing::MatcherInterface.
  //
  // Tests whether |status_container|'s OK value meets this matcher's
  // expectation.
  bool MatchAndExplain(
      const T &status_container,
      ::testing::MatchResultListener *listener) const override {
    if (!status_container.ok()) {
      *listener << "which is not OK";
      return false;
    }
    return true;
  }
};

// IsOkMatcherGenerator is an intermediate object returned by gutils::IsOk().
// It implements implicit type-cast operators to supported matcher types:
// Matcher<const absl::Status &> and Matcher<const absl::StatusOr<T> &>. These
// typecast operators create gMock matchers that test OK expectations on a
// status container.
class IsOkMatcherGenerator {
 public:
  // Type-cast operator for Matcher<const absl::Status &>.
  operator ::testing::Matcher<const absl::Status &>() const {
    return ::testing::MakeMatcher(
        new internal::IsOkMatcherImpl<const absl::Status &>());
  }

  // Type-cast operator for Matcher<const absl::StatusOr<T> &>.
  template <class T>
  operator ::testing::Matcher<const absl::StatusOr<T> &>() const {
    return ::testing::MakeMatcher(
        new internal::IsOkMatcherImpl<const absl::StatusOr<T> &>());
  }
};

}  // namespace internal

namespace testing {
namespace status {

namespace internal = ::gutils::internal;

// Returns a gMock matcher that expects an absl::StatusOr<T> object to have an
// OK status and for the contained T object to match |value_matcher|.
//
// Example:
//
//     absl::StatusOr<string> raven_speech_result = raven.Speak();
//     EXPECT_THAT(raven_speech_result, IsOkAndHolds(HasSubstr("nevermore")));
//
// If foo is an object of type T and foo_result is an object of type
// absl::StatusOr<T>, you can write:
//
//     EXPECT_THAT(foo_result, IsOkAndHolds(foo));
//
// instead of:
//
//     EXPECT_THAT(foo_result, IsOkAndHolds(Eq(foo)));
template <typename ValueMatcherT>
internal::IsOkAndHoldsGenerator<ValueMatcherT> IsOkAndHolds(
    ValueMatcherT value_matcher) {
  return internal::IsOkAndHoldsGenerator<ValueMatcherT>(value_matcher);
}

// Returns a gMock matcher that expects an absl::Status object to have the
// given |code|.
template <typename Enum>
internal::StatusIsMatcherGenerator<Enum> StatusIs(Enum code) {
  return internal::StatusIsMatcherGenerator<Enum>(code, absl::nullopt);
}

// Returns a gMock matcher that expects an absl::Status object to have the
// given |code| and |message|.
template <typename Enum>
internal::StatusIsMatcherGenerator<Enum> StatusIs(Enum code,
                                                  absl::string_view message) {
  return internal::StatusIsMatcherGenerator<Enum>(code, message);
}

// Returns an internal::IsOkMatcherGenerator, which may be typecast to a
// Matcher<absl::Status> or Matcher<absl::StatusOr<T>>. These gMock
// matchers test that a given status container has an OK status.
inline internal::IsOkMatcherGenerator IsOk() {
  return internal::IsOkMatcherGenerator();
}

}  // namespace status
}  // namespace testing

// Macros for testing the results of functions that return absl::Status or
// absl::StatusOr<T> (for any type T).
#define EXPECT_OK(rexpr) EXPECT_THAT(rexpr, ::gutils::testing::status::IsOk())
#define ASSERT_OK(rexpr) ASSERT_THAT(rexpr, ::gutils::testing::status::IsOk())

// Executes an expression that returns an absl::StatusOr<T>, and assigns the
// contained variable to lhs if the error code is OK.
// If the absl::Status is non-OK, generates a test failure and returns from the
// current function, which must have a void return type.
//
// Example: Assigning to an existing value
//   ASSERT_OK_AND_ASSIGN(ValueType value, MaybeGetValue(arg));
//
// The value assignment example might expand into:
//   absl::StatusOr<ValueType> status_or_value = MaybeGetValue(arg);
//   ASSERT_OK(status_or_value.status());
//   ValueType value = status_or_value.value();
#define ASSERT_OK_AND_ASSIGN(lhs, rexpr)                                  \
  IREE_ASSERT_OK_AND_ASSIGN_IMPL(                                         \
      IREE_STATUS_MACROS_CONCAT_NAME(_status_or_value, __COUNTER__), lhs, \
      rexpr);

#define IREE_ASSERT_OK_AND_ASSIGN_IMPL(statusor, lhs, rexpr) \
  auto statusor = (rexpr);                                   \
  ASSERT_OK(statusor.status()) << statusor.status();         \
  lhs = std::move(statusor.value())
#define IREE_STATUS_MACROS_CONCAT_NAME(x, y) \
  IREE_STATUS_MACROS_CONCAT_IMPL(x, y)
#define IREE_STATUS_MACROS_CONCAT_IMPL(x, y) x##y

// Implements the PrintTo() method for absl::StatusOr<T>. This method is
// used by gUnit to print absl::StatusOr<T> objects for debugging. The
// implementation relies on gUnit for printing values of T when a
// absl::StatusOr<T> object is OK and contains a value.
template <typename T>
void PrintTo(const absl::StatusOr<T> &statusor, std::ostream *os) {
  if (!statusor.ok()) {
    *os << statusor.status();
  } else {
    *os << absl::StrCat("OK: ", ::testing::PrintToString(statusor.value()));
  }
}

}  // namespace gutils

#endif  // GUTILS_INTERNAL_STATUS_MATCHERS_H_
