#include "p4_constraints/backend/errors.h"

#include <string>

#include "absl/status/statusor.h"
#include "gutils/source_location.h"
#include "gutils/status.h"
#include "gutils/status_builder.h"
#include "p4_constraints/ast.pb.h"
#include "p4_constraints/constraint_source.h"
#include "p4_constraints/quote.h"

namespace p4_constraints {

gutils::StatusBuilder RuntimeTypeError(const ConstraintSource& source,
                                       const ast::SourceLocation& start,
                                       const ast::SourceLocation& end) {
  absl::StatusOr<std::string> quote = QuoteSubConstraint(source, start, end);
  if (!quote.ok()) {
    return gutils::InternalErrorBuilder(GUTILS_LOC)
           << "Failed to quote sub-constraint: "
           << gutils::StableStatusToString(quote.status());
  }
  return gutils::InternalErrorBuilder(GUTILS_LOC)
         << *quote << "Runtime type error: ";
}

}  // namespace p4_constraints
