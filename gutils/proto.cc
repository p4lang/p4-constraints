#include "gutils/proto.h"

#include <fcntl.h>

#include <string>
#include <string_view>

#include "absl/status/status.h"
#include "absl/strings/substitute.h"
#include "google/protobuf/io/tokenizer.h"
#include "google/protobuf/message.h"
#include "google/protobuf/text_format.h"
#include "google/protobuf/util/message_differencer.h"
#include "gutils/source_location.h"
#include "gutils/status_builder.h"

namespace gutils {

// Collects errors by appending them to a given string.
class StringErrorCollector : public google::protobuf::io::ErrorCollector {
 public:
  // String error_text is unowned and must remain valid during the use of
  // StringErrorCollector.
  explicit StringErrorCollector(std::string *error_text)
      : error_text_{error_text} {};
  StringErrorCollector(const StringErrorCollector &) = delete;
  StringErrorCollector &operator=(const StringErrorCollector &) = delete;

  // Implementation of protobuf::io::ErrorCollector::RecordError.
  void RecordError(int line, int column, std::string_view message) override {
    if (error_text_ != nullptr) {
      absl::SubstituteAndAppend(error_text_, "$0($1): $2\n", line, column,
                                message);
    }
  }

  // Implementation of protobuf::io::ErrorCollector::RecordWarning.
  void RecordWarning(int line, int column, std::string_view message) override {
    RecordError(line, column, message);
  }

 private:
  std::string *const error_text_;
};

bool ProtoEqual(const google::protobuf::Message &message1,
                const google::protobuf::Message &message2,
                google::protobuf::util::MessageDifferencer &differ) {
  if (message1.GetDescriptor() != message2.GetDescriptor()) {
    return false;
  }

  return differ.Compare(message1, message2);
}
// Calls `ProtoEqual` with default MessageDifferencer.
bool ProtoEqual(const google::protobuf::Message &message1,
                const google::protobuf::Message &message2) {
  google::protobuf::util::MessageDifferencer differ =
      google::protobuf::util::MessageDifferencer();
  return ProtoEqual(message1, message2, differ);
}

absl::Status ReadProtoFromString(std::string_view proto_string,
                                 google::protobuf::Message *message) {
  // Verifies that the version of the library that we linked against is
  // compatible with the version of the headers we compiled against.
  /* copybara:insert(not needed nor possible in google3, as it is a mono repo)
  GOOGLE_PROTOBUF_VERIFY_VERSION;
  */

  google::protobuf::TextFormat::Parser parser;
  std::string all_errors;
  StringErrorCollector collector(&all_errors);
  parser.RecordErrorsTo(&collector);

  if (!parser.ParseFromString(std::string(proto_string), message)) {
    return InvalidArgumentErrorBuilder(GUTILS_LOC)
           << "string <" << proto_string << "> did not parse as a"
           << message->GetTypeName() << ":\n"
           << all_errors;
  }

  return absl::OkStatus();
}

}  // namespace gutils
