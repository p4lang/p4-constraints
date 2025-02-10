/*
 * Copyright 2022 The P4-Constraints Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

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
