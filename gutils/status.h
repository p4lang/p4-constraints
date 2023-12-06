#ifndef THIRD_PARTY_P4LANG_P4_CONSTRAINTS_GUTILS_STATUS_H_
#define THIRD_PARTY_P4LANG_P4_CONSTRAINTS_GUTILS_STATUS_H_

#include <string>

#include "absl/status/status.h"

namespace gutils {

// Converts `status` to a readable string. The current absl `ToString` method is
// not stable, which causes issues while golden testing. This function is
// stable.
std::string StableStatusToString(const absl::Status& status);

}  // namespace gutils

#endif  // THIRD_PARTY_P4LANG_P4_CONSTRAINTS_GUTILS_STATUS_H_
