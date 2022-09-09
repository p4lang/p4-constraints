#include "gutils/status.h"

#include <string>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"

namespace gutils {

std::string StableStatusToString(const absl::Status& status) {
  return absl::StrCat(absl::StatusCodeToString(status.code()), ": ",
                      status.message(), "\n");
}

}  // namespace gutils
