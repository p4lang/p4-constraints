#ifndef THIRD_PARTY_P4LANG_P4_CONSTRAINTS_GUTILS_PROTO_H_
#define THIRD_PARTY_P4LANG_P4_CONSTRAINTS_GUTILS_PROTO_H_

#include <string_view>

#include "absl/status/status.h"
#include "google/protobuf/message.h"
#include "google/protobuf/util/message_differencer.h"

namespace gutils {

// Returns result of equality comparison of given proto messages. A `differ` can
// optionally be provided for fine-grained control over how to compute the diff.
bool ProtoEqual(const google::protobuf::Message &message1,
                const google::protobuf::Message &message2,
                google::protobuf::util::MessageDifferencer &differ);
bool ProtoEqual(const google::protobuf::Message &message1,
                const google::protobuf::Message &message2);

// Read the contents of the string into a protobuf.
absl::Status ReadProtoFromString(std::string_view proto_string,
                                 google::protobuf::Message *message);

}  //  namespace gutils

#endif  // THIRD_PARTY_P4LANG_P4_CONSTRAINTS_GUTILS_PROTO_H_
