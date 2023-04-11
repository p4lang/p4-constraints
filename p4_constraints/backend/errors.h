#ifndef THIRD_PARTY_P4LANG_P4_CONSTRAINTS_P4_CONSTRAINTS_BACKEND_ERRORS_H_
#define THIRD_PARTY_P4LANG_P4_CONSTRAINTS_P4_CONSTRAINTS_BACKEND_ERRORS_H_

#include "gutils/status_builder.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/constraint_source.h"

namespace p4_constraints {

// Returns an InternalError for a runtime type mismatch with in-depth,
// human-readable source information. Should only be used for expressions that
// are known to be type-checked since this makes it an InternalError.
gutils::StatusBuilder RuntimeTypeError(const ConstraintSource& source,
                                       const ast::SourceLocation& start,
                                       const ast::SourceLocation& end);
}  // namespace p4_constraints

#endif  // THIRD_PARTY_P4LANG_P4_CONSTRAINTS_P4_CONSTRAINTS_BACKEND_ERRORS_H_
