// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

// #include "intel_drng_copy.h"

#include <stddef.h>

unsigned int rdrand_get_bytes(unsigned int n, unsigned char* dest);

int randombytes(void* buf, size_t n)
{
  return rdrand_get_bytes(n, buf);
}
