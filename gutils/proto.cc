#include "gutils/proto.h"

#include "google/protobuf/message.h"
#include "google/protobuf/util/message_differencer.h"

namespace gutils {

bool ProtoEqual(const google::protobuf::Message &message1,
                const google::protobuf::Message &message2,
                google::protobuf::util::MessageDifferencer &differ) {
  if (message1.GetDescriptor() != message2.GetDescriptor()) {
    return false;
  }

  return differ.Compare(message1, message2);
}
// Calls `ProtoEqual` with default MessageDifferencer
bool ProtoEqual(const google::protobuf::Message &message1,
                const google::protobuf::Message &message2) {
  google::protobuf::util::MessageDifferencer differ =
      google::protobuf::util::MessageDifferencer();
  return ProtoEqual(message1, message2, differ);
}

}  // namespace gutils
