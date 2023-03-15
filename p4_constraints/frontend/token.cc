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

#include "p4_constraints/frontend/token.h"

#include <string>
#include <utility>

#include "absl/container/flat_hash_map.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/types/optional.h"

namespace p4_constraints {

// All token kinds. Keep in sync with enum Kind in token.h.
const Token::Kind Token::kAllKinds[25] = {
    // clang-format off
  TRUE,
  FALSE,
  BANG,
  AND,
  OR,
  IMPLIES,
  MINUS,
  DOT,
  DOUBLE_COLON,
  SEMICOLON,
  EQ,
  NE,
  GT,
  GE,
  LT,
  LE,
  LPAR,
  RPAR,
  ID,
  BINARY,
  OCTARY,
  DECIMAL,
  HEXADEC,
  END_OF_INPUT,
  UNEXPECTED_CHAR,
    // clang-format on
};

std::string Token::KindToKeyword(Token::Kind token_kind) {
  switch (token_kind) {
    case Token::TRUE:
      return "true";
    case Token::FALSE:
      return "false";
    case Token::BANG:
      return "!";
    case Token::AND:
      return "&&";
    case Token::OR:
      return "||";
    case Token::IMPLIES:
      return "->";
    case Token::MINUS:
      return "-";
    case Token::DOT:
      return ".";
    case Token::DOUBLE_COLON:
      return "::";
    case Token::SEMICOLON:
      return ";";
    case Token::EQ:
      return "==";
    case Token::NE:
      return "!=";
    case Token::GT:
      return ">";
    case Token::GE:
      return ">=";
    case Token::LT:
      return "<";
    case Token::LE:
      return "<=";
    case Token::LPAR:
      return "(";
    case Token::RPAR:
      return ")";
    case Token::ID:
      return "<ID>";
    case Token::BINARY:
      return "<BINARY>";
    case Token::OCTARY:
      return "<OCTARY>";
    case Token::DECIMAL:
      return "<DECIMAL>";
    case Token::HEXADEC:
      return "<HEXADEC>";
    case Token::END_OF_INPUT:
      return "<END_OF_INPUT>";
    case Token::UNEXPECTED_CHAR:
      return "<UNEXPECTED_CHAR>";
    default:
      LOG(ERROR) << "non-existent token kind";
      return "<UNKNOWN>";
  }
}

const absl::flat_hash_map<std::string, Token::Kind>* const kind_keyword_map =
    []() {
      auto* map = new absl::flat_hash_map<std::string, Token::Kind>();
      for (Token::Kind kind : Token::kAllKinds) {
        auto it = map->insert({Token::KindToKeyword(kind), kind});
        DCHECK(it.second) << "Token::KindToKeyword must be injective";
      }
      return map;
    }();

absl::optional<Token::Kind> Token::KeywordToKind(const std::string& keyword) {
  auto kind = kind_keyword_map->find(keyword);
  if (kind == kind_keyword_map->end()) {
    return {};
  } else {
    return {kind->second};
  }
}

std::ostream& operator<<(std::ostream& os, Token::Kind kind) {
  return os << Token::KindToKeyword(kind);
}

}  // namespace p4_constraints
