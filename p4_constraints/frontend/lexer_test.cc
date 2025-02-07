// Copyright 2020 The P4-Constraints Authors
// SPDX-License-Identifier: Apache-2.0
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

#include "p4_constraints/frontend/lexer.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "p4_constraints/ast.pb.h"
#include "p4_constraints/constraint_source.h"
#include "p4_constraints/frontend/token.h"

namespace p4_constraints {

using ::testing::ElementsAre;
using ::testing::Eq;
using ::testing::Field;

std::vector<Token::Kind> GetTokenKinds(std::vector<Token>& tokens) {
  std::vector<Token::Kind> token_kinds;
  for (const auto& token : tokens) {
    token_kinds.push_back(token.kind);
  }
  return token_kinds;
}

// Test that all reserved keywords can be lexed.
TEST(LexerTest, AllKeywordsAreRecognized) {
  std::vector<Token::Kind> keyword_kinds;

  // Test that keywords can be lexed individually.
  for (Token::Kind kind : Token::kAllKinds) {
    std::string keyword = Token::KindToKeyword(kind);
    ASSERT_GT(keyword.size(), 0);
    if (keyword.front() == '<' && keyword.back() == '>') continue;
    ConstraintSource source{
        .constraint_string = keyword,
        .constraint_location = ast::SourceLocation(),
    };
    EXPECT_THAT(Tokenize(source),
                ElementsAre(Field(&Token::kind, Eq(kind)),
                            Field(&Token::kind, Eq(Token::END_OF_INPUT))));
    keyword_kinds.push_back(kind);
  }

  // Test that keywords can also be lexed together.
  std::stringstream input;
  for (Token::Kind kind : keyword_kinds) {
    input << kind << " ";
  }
  ConstraintSource source{
      .constraint_string = input.str(),
      .constraint_location = ast::SourceLocation(),
  };
  auto tokens = Tokenize(source);
  ASSERT_THAT(tokens.size(), keyword_kinds.size() + 1);
  EXPECT_THAT(tokens.back(), Field(&Token::kind, Eq(Token::END_OF_INPUT)));
  for (int i = 0; i < keyword_kinds.size(); i++) {
    EXPECT_EQ(tokens[i].kind, keyword_kinds[i]);
  }
}

// Test that certain strings DO lex to particular tokens.
TEST(LexerTest, PositiveSingleToken) {
  const std::pair<std::string, std::vector<Token::Kind>> tests[] = {
      {"true", {Token::TRUE, Token::END_OF_INPUT}},
      {"false", {Token::FALSE, Token::END_OF_INPUT}},
      {"!", {Token::BANG, Token::END_OF_INPUT}},
      {"&&", {Token::AND, Token::END_OF_INPUT}},
      {"||", {Token::OR, Token::END_OF_INPUT}},
      {"->", {Token::IMPLIES, Token::END_OF_INPUT}},
      {".", {Token::DOT, Token::END_OF_INPUT}},
      {"::", {Token::DOUBLE_COLON, Token::END_OF_INPUT}},
      {"(", {Token::LPAR, Token::END_OF_INPUT}},
      {")", {Token::RPAR, Token::END_OF_INPUT}},
      // binary operators
      {"<", {Token::LT, Token::END_OF_INPUT}},
      {"<=", {Token::LE, Token::END_OF_INPUT}},
      {"==", {Token::EQ, Token::END_OF_INPUT}},
      {"!=", {Token::NE, Token::END_OF_INPUT}},
      {">", {Token::GT, Token::END_OF_INPUT}},
      {">=", {Token::GE, Token::END_OF_INPUT}},
      // keys
      {"_", {Token::ID, Token::END_OF_INPUT}},
      {"d", {Token::ID, Token::END_OF_INPUT}},
      {"D", {Token::ID, Token::END_OF_INPUT}},
      {"__", {Token::ID, Token::END_OF_INPUT}},
      {"a1234567890", {Token::ID, Token::END_OF_INPUT}},
      {"_._", {Token::ID, Token::DOT, Token::ID, Token::END_OF_INPUT}},
      {"_.d._01234567890.a0.b1",
       {Token::ID, Token::DOT, Token::ID, Token::DOT, Token::ID, Token::DOT,
        Token::ID, Token::DOT, Token::ID, Token::END_OF_INPUT}},
      {"_.3", {Token::ID, Token::DOT, Token::DECIMAL, Token::END_OF_INPUT}},
      // decimal numerals
      {"0", {Token::DECIMAL, Token::END_OF_INPUT}},
      {"00", {Token::DECIMAL, Token::END_OF_INPUT}},
      {"000", {Token::DECIMAL, Token::END_OF_INPUT}},
      {"00001", {Token::DECIMAL, Token::END_OF_INPUT}},
      {"1234567890", {Token::DECIMAL, Token::END_OF_INPUT}},
      {"0d0", {Token::DECIMAL, Token::END_OF_INPUT}},
      {"0d1234567890", {Token::DECIMAL, Token::END_OF_INPUT}},
      {"0D0", {Token::DECIMAL, Token::END_OF_INPUT}},
      {"0D1234567890", {Token::DECIMAL, Token::END_OF_INPUT}},
      // binary numerals
      {"0b0", {Token::BINARY, Token::END_OF_INPUT}},
      {"0b1", {Token::BINARY, Token::END_OF_INPUT}},
      {"0b00", {Token::BINARY, Token::END_OF_INPUT}},
      {"0b01", {Token::BINARY, Token::END_OF_INPUT}},
      {"0b10", {Token::BINARY, Token::END_OF_INPUT}},
      {"0b11", {Token::BINARY, Token::END_OF_INPUT}},
      {"0B0", {Token::BINARY, Token::END_OF_INPUT}},
      {"0B1", {Token::BINARY, Token::END_OF_INPUT}},
      {"0B00", {Token::BINARY, Token::END_OF_INPUT}},
      {"0B01", {Token::BINARY, Token::END_OF_INPUT}},
      {"0B10", {Token::BINARY, Token::END_OF_INPUT}},
      {"0B11", {Token::BINARY, Token::END_OF_INPUT}},
      {"0b012", {Token::BINARY, Token::DECIMAL, Token::END_OF_INPUT}},
      {"0b01 2", {Token::BINARY, Token::DECIMAL, Token::END_OF_INPUT}},
      {"0b01a", {Token::BINARY, Token::ID, Token::END_OF_INPUT}},
      {"0b01 a", {Token::BINARY, Token::ID, Token::END_OF_INPUT}},
      // octal numerals
      {"0o0", {Token::OCTARY, Token::END_OF_INPUT}},
      {"0o1", {Token::OCTARY, Token::END_OF_INPUT}},
      {"0o00", {Token::OCTARY, Token::END_OF_INPUT}},
      {"0o001", {Token::OCTARY, Token::END_OF_INPUT}},
      {"0o12345670", {Token::OCTARY, Token::END_OF_INPUT}},
      {"0O0", {Token::OCTARY, Token::END_OF_INPUT}},
      {"0O1", {Token::OCTARY, Token::END_OF_INPUT}},
      {"0O00", {Token::OCTARY, Token::END_OF_INPUT}},
      {"0O001", {Token::OCTARY, Token::END_OF_INPUT}},
      {"0O12345670", {Token::OCTARY, Token::END_OF_INPUT}},
      // {"0o128", {Token::UNEXPECTED_CHAR}},
      {"0o128", {Token::OCTARY, Token::DECIMAL, Token::END_OF_INPUT}},
      {"0o12 8", {Token::OCTARY, Token::DECIMAL, Token::END_OF_INPUT}},
      // {"0o23a", {Token::UNEXPECTED_CHAR}},
      {"0o23a", {Token::OCTARY, Token::ID, Token::END_OF_INPUT}},
      {"0o23 a", {Token::OCTARY, Token::ID, Token::END_OF_INPUT}},
      // hexadecimal numerals
      {"0x0", {Token::HEXADEC, Token::END_OF_INPUT}},
      {"0x1", {Token::HEXADEC, Token::END_OF_INPUT}},
      {"0x00", {Token::HEXADEC, Token::END_OF_INPUT}},
      {"0x001", {Token::HEXADEC, Token::END_OF_INPUT}},
      {"0x1234567890aAbBcCdDeEfF", {Token::HEXADEC, Token::END_OF_INPUT}},
      {"0X0", {Token::HEXADEC, Token::END_OF_INPUT}},
      {"0X1", {Token::HEXADEC, Token::END_OF_INPUT}},
      {"0X00", {Token::HEXADEC, Token::END_OF_INPUT}},
      {"0X001", {Token::HEXADEC, Token::END_OF_INPUT}},
      {"0X1234567890aAbBcCdDeEfF", {Token::HEXADEC, Token::END_OF_INPUT}},
      // {"0xfF0o", {Token::UNEXPECTED_CHAR}},
      {"0xfF0o", {Token::HEXADEC, Token::ID, Token::END_OF_INPUT}},
      {"0xfF0 o", {Token::HEXADEC, Token::ID, Token::END_OF_INPUT}},
      // end of file
      {"", {Token::END_OF_INPUT}},
      // unexpected character
      {"@", {Token::UNEXPECTED_CHAR}},
      {"#", {Token::UNEXPECTED_CHAR}},
      {"$", {Token::UNEXPECTED_CHAR}},
      {"%", {Token::UNEXPECTED_CHAR}},
      {"^", {Token::UNEXPECTED_CHAR}},
      {"&", {Token::UNEXPECTED_CHAR}},
      {"*", {Token::UNEXPECTED_CHAR}},
      {"+", {Token::UNEXPECTED_CHAR}},
      {"=", {Token::UNEXPECTED_CHAR}},
      {"~", {Token::UNEXPECTED_CHAR}},
      {"|", {Token::UNEXPECTED_CHAR}},
      {"\\", {Token::UNEXPECTED_CHAR}},
      {"/", {Token::UNEXPECTED_CHAR}},
      {"{", {Token::UNEXPECTED_CHAR}},
      {"}", {Token::UNEXPECTED_CHAR}},
      {"[", {Token::UNEXPECTED_CHAR}},
      {"]", {Token::UNEXPECTED_CHAR}},
      {"`", {Token::UNEXPECTED_CHAR}},
      // It is easier to let the lexer accept such strings and handle the
      // problem in the parser.
      // {"0b2", {Token::UNEXPECTED_CHAR}},
      // {"0o8", {Token::UNEXPECTED_CHAR}},
      // {"0df", {Token::UNEXPECTED_CHAR}},
      // {"0xg", {Token::UNEXPECTED_CHAR}},
      {"0b2", {Token::DECIMAL, Token::ID, Token::END_OF_INPUT}},
      {"0o8", {Token::DECIMAL, Token::ID, Token::END_OF_INPUT}},
      {"0df", {Token::DECIMAL, Token::ID, Token::END_OF_INPUT}},
      {"0xg", {Token::DECIMAL, Token::ID, Token::END_OF_INPUT}},
  };

  for (const auto& test : tests) {
    const auto& str = test.first;
    const auto& expected_tokens = test.second;
    ConstraintSource source{
        .constraint_string = str,
        .constraint_location = ast::SourceLocation(),
    };
    auto actual_tokens = Tokenize(source);
    for (int i = 0; i < expected_tokens.size(); ++i) {
      EXPECT_EQ(actual_tokens[i].kind, expected_tokens[i])
          << "[!] Token " << (i + 1) << " in '" << str << "' unexpected.\n"
          << "[!] Expected " << expected_tokens[i] << ", got "
          << actual_tokens[i].kind << "\n";
    }
  }
}

// Test that certain strings DO NOT lex to particular tokens.
TEST(LexerTest, NegativeToken) {
  const std::pair<std::string, Token::Kind> tests[] = {
      // common_typos_disable - so Critique doesn't complain
      {"True", Token::TRUE},
      {"trUe", Token::TRUE},
      {"ture", Token::TRUE},
      {"False", Token::FALSE},
      {"falsE", Token::FALSE},
      {"FALSE", Token::FALSE},
      {"fasle", Token::FALSE},
      // common_typos_enable
      {"~", Token::BANG},
      {"not", Token::BANG},
      {"&", Token::AND},
      {"and", Token::AND},
      {"|", Token::OR},
      {"or", Token::OR},
      {"=>", Token::IMPLIES},
      {"implies", Token::IMPLIES},
      {"{", Token::LPAR},
      {"begin", Token::LPAR},
      {"}", Token::RPAR},
      {"end", Token::RPAR},
      // fields
      {".", Token::ID},
      {"..", Token::ID},
      {".abc", Token::ID},
      {"7", Token::ID},
      {".abc", Token::ID},
      // decimal numerals
      {"+0", Token::DECIMAL},
      {"-0", Token::DECIMAL},
      // binary numerals
      {"+0b0", Token::BINARY},
      {"-0b1", Token::BINARY},
      {"0b2", Token::BINARY},
  };

  for (const auto& test : tests) {
    const auto& str = test.first;
    const auto& bad_token = test.second;
    ConstraintSource source{
        .constraint_string = str,
        .constraint_location = ast::SourceLocation(),
    };
    auto tokens = Tokenize(source);
    EXPECT_NE(tokens[0].kind, bad_token)
        << "[!] String \"" << str << "\" incorrectly lexed as token"
        << bad_token << ".\n";
  }
}

TEST(LexerTest, CommentsAreLexedCorrectly) {
  std::pair<std::string, std::vector<Token::Kind>> tests[] = {
      {"// just a comment", {Token::END_OF_INPUT}},
      {"// comment followed by token\ntrue",
       {Token::TRUE, Token::END_OF_INPUT}},
      {"true // trailing comment\n false",
       {Token::TRUE, Token::FALSE, Token::END_OF_INPUT}},
      {"/* just a\n multiline\n comment */", {Token::END_OF_INPUT}},
      {"/* comment followed by token\n*/true",
       {Token::TRUE, Token::END_OF_INPUT}},
      {"true /* trailing comment */ false",
       {Token::TRUE, Token::FALSE, Token::END_OF_INPUT}},
  };

  for (const auto& test : tests) {
    const auto& str = test.first;
    const auto& expected_tokens = test.second;
    ConstraintSource source{
        .constraint_string = str,
        .constraint_location = ast::SourceLocation(),
    };
    auto actual_tokens = Tokenize(source);
    for (int i = 0; i < expected_tokens.size(); ++i) {
      EXPECT_EQ(actual_tokens[i].kind, expected_tokens[i])
          << "[!] Token " << (i + 1) << " in '" << str << "' unexpected.\n"
          << "[!] Expected " << expected_tokens[i] << ", got "
          << actual_tokens[i].kind << "\n";
    }
  }
}

TEST(LexerTest, TokenizeAnEmptyString) {
  std::vector<Token> empty_str_tokens = Tokenize({
      .constraint_string = "''",
      .constraint_location = ast::SourceLocation(),
  });
  EXPECT_THAT(GetTokenKinds(empty_str_tokens),
              ElementsAre(Token::STRING, Token::END_OF_INPUT));
  EXPECT_THAT(empty_str_tokens[0].text, "");
}

TEST(LexerTest, TokenizeAnEmptyStringWithADoubleQuoteInMiddle) {
  std::vector<Token> double_quote_in_middle_str_tokens = Tokenize({
      .constraint_string = "'''",
      .constraint_location = ast::SourceLocation(),
  });
  EXPECT_THAT(GetTokenKinds(double_quote_in_middle_str_tokens),
              ElementsAre(Token::STRING, Token::UNEXPECTED_CHAR));
}

TEST(LexerTest, TokenizeString) {
  auto str_tokens = Tokenize({
      .constraint_string = "'192.168.2.1'",
      .constraint_location = ast::SourceLocation(),
  });
  EXPECT_THAT(GetTokenKinds(str_tokens),
              testing::ElementsAre(Token::STRING, Token::END_OF_INPUT));
  EXPECT_THAT(str_tokens[0].text, "192.168.2.1");
}

TEST(LexerTest, TokenizeIPv4SingleQuoteString) {
  auto single_quote_str_tokens = Tokenize({
      .constraint_string = "ipv4('192.168.2.1')",
      .constraint_location = ast::SourceLocation(),
  });
  EXPECT_THAT(GetTokenKinds(single_quote_str_tokens),
              testing::ElementsAre(Token::ID, Token::LPAR, Token::STRING,
                                   Token::RPAR, Token::END_OF_INPUT));
}

TEST(LexerTest, TokenizeIPv4DoubleQuoteString) {
  auto double_quote_str_tokens = Tokenize({
      .constraint_string = "ipv4(\"192.168.2.1\")",
      .constraint_location = ast::SourceLocation(),
  });
  EXPECT_THAT(
      GetTokenKinds(double_quote_str_tokens),
      testing::ElementsAre(Token::ID, Token::LPAR, Token::UNEXPECTED_CHAR));
}

TEST(LexerTest, TokenizeIPv4MixedQuoteString) {
  auto mixed_quote_str_tokens = Tokenize({
      .constraint_string = "ipv4(\"192.168.2.1')",
      .constraint_location = ast::SourceLocation(),
  });
  EXPECT_THAT(
      GetTokenKinds(mixed_quote_str_tokens),
      testing::ElementsAre(Token::ID, Token::LPAR, Token::UNEXPECTED_CHAR));
}

TEST(LexerTest, TokenizeIPv4ReverseMixedQuoteString) {
  auto reverse_mixed_quote_str_tokens = Tokenize({
      .constraint_string = "ipv4('192.168.2.1\")",
      .constraint_location = ast::SourceLocation(),
  });
  EXPECT_THAT(
      GetTokenKinds(reverse_mixed_quote_str_tokens),
      testing::ElementsAre(Token::ID, Token::LPAR, Token::UNEXPECTED_CHAR));
}

}  // namespace p4_constraints
