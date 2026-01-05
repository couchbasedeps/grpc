//
//
// Copyright 2026 gRPC authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//

#ifndef GRPC_TEST_CORE_END2END_FIXTURES_HTTP_COMMON_SECURE_FIXTURES_H
#define GRPC_TEST_CORE_END2END_FIXTURES_HTTP_COMMON_SECURE_FIXTURES_H

#include <grpc/credentials.h>
#include <grpc/grpc.h>
#include <grpc/status.h>

#include "src/core/lib/channel/channel_args.h"
#include "test/core/end2end/fixtures/proxy.h"
#include "test/core/end2end/fixtures/secure_fixture.h"
#include "absl/functional/any_invocable.h"

namespace grpc_core {
class FakesecFixture : public SecureFixture {
 private:
  grpc_channel_credentials* MakeClientCreds(const ChannelArgs&) override;
  grpc_server_credentials* MakeServerCreds(const ChannelArgs& args) override;
};

class InsecureCredsFixture : public InsecureFixture {
 private:
  grpc_server_credentials* MakeServerCreds(const ChannelArgs& args) override;
};

class SslProxyFixture : public CoreTestFixture {
 public:
  SslProxyFixture(const ChannelArgs& client_args,
                  const ChannelArgs& server_args);
  ~SslProxyFixture() override;

 private:
  static grpc_server* CreateProxyServer(const char* port,
                                        const grpc_channel_args* server_args);

  static grpc_channel* CreateProxyClient(const char* target,
                                         const grpc_channel_args* client_args);

  grpc_server* MakeServer(
      const ChannelArgs& args, grpc_completion_queue* cq,
      absl::AnyInvocable<void(grpc_server*)>& pre_server_start) override;

  grpc_channel* MakeClient(const ChannelArgs& args,
                           grpc_completion_queue* cq) override;

  const grpc_end2end_proxy_def proxy_def_;
  grpc_end2end_proxy* proxy_;
};

}  // namespace grpc_core

#endif  // GRPC_TEST_CORE_END2END_FIXTURES_HTTP_COMMON_SECURE_FIXTURES_H
