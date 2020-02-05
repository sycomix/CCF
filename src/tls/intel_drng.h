// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "intel_drng_copy.h"

#include <utility>
#include <vector>

namespace tls
{
  using rng_func_t = int (*)(void* ctx, unsigned char* output, size_t len);

  class Entropy
  {
  public:
    virtual void* get_data() = 0;
    virtual rng_func_t get_rng() = 0;
    virtual std::vector<uint8_t> random(size_t len) = 0;
    virtual ~Entropy() {}
  };

  class IntelDRNG : public Entropy
  {
  public:
    IntelDRNG()
    {
      if (!is_drng_supported())
        throw std::logic_error("No support for RDRAND / RDSEED on this CPU.");
    }

    std::vector<uint8_t> random(size_t len) override
    {
      unsigned char buf[len];

      if (rdrand_get_bytes(len, buf) < len)
        throw std::logic_error("Couldn't create random data");

      return std::vector<uint8_t>(buf, buf + len);
    }

    static int rng(void*, unsigned char* output, size_t len)
    {
      if (rdrand_get_bytes(len, output) < len)
        throw std::logic_error("Couldn't create random data");
      return 0;
    }

    rng_func_t get_rng() override
    {
      return &rng;
    }

    void* get_data() override
    {
      return this;
    }

    static bool is_drng_supported()
    {
      return (get_drng_support() & (DRNG_HAS_RDRAND | DRNG_HAS_RDSEED)) ==
        (DRNG_HAS_RDRAND | DRNG_HAS_RDSEED);
    }
  };
}
