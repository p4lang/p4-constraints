// Copyright 2019 The MediaPipe Authors.
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

#ifndef MEDIAPIPE_PORT_PARSE_TEXT_PROTO_H_
#define MEDIAPIPE_PORT_PARSE_TEXT_PROTO_H_

#include "glog/logging.h"
#include "google/protobuf/text_format.h"

namespace util {

template <typename T>
T ParseTextProtoOrDie(const std::string& input) {
  T result;
  CHECK(google::protobuf::TextFormat::ParseFromString(input, &result));
  return result;
}

}  // namespace util

#endif  // MEDIAPIPE_PORT_PARSE_TEXT_PROTO_H_
