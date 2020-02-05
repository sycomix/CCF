// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_recovery.h"

#include <mbedtls/pem.h>
#ifdef MOD_MBEDTLS
#  include <mbedtls/eddsa.h>
#endif

namespace tls
{
  enum class CurveImpl
  {
    secp384r1 = 1,
#ifdef MOD_MBEDTLS
    ed25519 = 2,
#endif
    secp256k1_mbedtls = 3,
    secp256k1_bitcoin = 4,

#if SERVICE_IDENTITY_CURVE_CHOICE_SECP384R1
    service_identity_curve_choice = secp384r1,
#elif SERVICE_IDENTITY_CURVE_CHOICE_ED25519
    service_identity_curve_choice = ed25519,
#elif SERVICE_IDENTITY_CURVE_CHOICE_SECP256K1_MBEDTLS
    service_identity_curve_choice = secp256k1_mbedtls,
#elif SERVICE_IDENTITY_CURVE_CHOICE_SECP256K1_BITCOIN
    service_identity_curve_choice = secp256k1_bitcoin,
#else
#  pragma message( \
    "No service identity curve specified - defaulting to secp384r1")
    service_identity_curve_choice = secp384r1,
#endif
  };

  static constexpr size_t max_pem_key_size = 2048;
  static constexpr size_t max_pem_cert_size = 4096;

  // As these are not exposed by mbedlts, define them here to allow simple
  // conversion from DER to PEM format
  static constexpr auto PEM_CERTIFICATE_HEADER =
    "-----BEGIN CERTIFICATE-----\n";
  static constexpr auto PEM_CERTIFICATE_FOOTER = "-----END CERTIFICATE-----\n";

  // 2 implementations of secp256k1 are available - mbedtls and bitcoin. Either
  // can be asked for explicitly via the CurveImpl enum. For cases where we
  // receive a raw 256k1 key/signature/cert only, this flag determines which
  // implementation is used
  static constexpr bool prefer_bitcoin_secp256k1 = true;

  // Helper to access elliptic curve id from context
  inline mbedtls_ecp_group_id get_ec_from_context(const mbedtls_pk_context& ctx)
  {
    return mbedtls_pk_ec(ctx)->grp.id;
  }

  // Get mbedtls elliptic curve for given CCF curve implementation
  inline mbedtls_ecp_group_id get_ec_for_curve_impl(CurveImpl curve)
  {
    switch (curve)
    {
      case CurveImpl::secp384r1:
      {
        return MBEDTLS_ECP_DP_SECP384R1;
      }
#ifdef MOD_MBEDTLS
      case CurveImpl::ed25519:
      {
        return MBEDTLS_ECP_DP_CURVE25519;
      }
#endif
      case CurveImpl::secp256k1_mbedtls:
      case CurveImpl::secp256k1_bitcoin:
      {
        return MBEDTLS_ECP_DP_SECP256K1;
      }
      default:
      {
        throw std::logic_error(
          "Unhandled curve type: " +
          std::to_string(static_cast<size_t>(curve)));
      }
    }
  }

  // Get message digest algorithm to use for given elliptic curve
  inline mbedtls_md_type_t get_md_for_ec(mbedtls_ecp_group_id ec)
  {
    switch (ec)
    {
      case MBEDTLS_ECP_DP_SECP384R1:
      {
        return MBEDTLS_MD_SHA384;
      }
#ifdef MOD_MBEDTLS
      case MBEDTLS_ECP_DP_CURVE25519:
      {
        return MBEDTLS_MD_SHA512;
      }
#endif
      case MBEDTLS_ECP_DP_SECP256K1:
      {
        return MBEDTLS_MD_SHA256;
      }
      default:
      {
        throw std::logic_error(
          std::string("Unhandled ecp group id: ") +
          mbedtls_ecp_curve_info_from_grp_id(ec)->name);
      }
    }
  }

  static void secp256k1_illegal_callback(const char* str, void*)
  {
    throw std::logic_error(
      fmt::format("[libsecp256k1] illegal argument: {}", str));
  }

  static constexpr size_t ecp_num_size = 100;

  inline void parse_secp256k_bc(
    const mbedtls_pk_context& ctx,
    secp256k1_context* bc_ctx,
    secp256k1_pubkey* bc_pub)
  {
    auto k = mbedtls_pk_ec(ctx);
    size_t pub_len;
    uint8_t pub_buf[ecp_num_size];

    int rc = mbedtls_ecp_point_write_binary(
      &k->grp,
      &k->Q,
      MBEDTLS_ECP_PF_COMPRESSED,
      &pub_len,
      pub_buf,
      ecp_num_size);
    if (rc != 0)
    {
      throw std::logic_error(
        "mbedtls_ecp_point_write_binary failed: " + error_string(rc));
    }

    rc = secp256k1_ec_pubkey_parse(bc_ctx, bc_pub, pub_buf, pub_len);
    if (rc != 1)
    {
      throw std::logic_error("secp256k1_ec_pubkey_parse failed");
    }
  }

  // Wrap calls to secp256k1_context_create, setting illegal callback to throw
  // catchable errors rather than aborting, and ensuring destroy is called when
  // this goes out of scope
  class BCk1Context
  {
  public:
    secp256k1_context* p = nullptr;

    BCk1Context(unsigned int flags)
    {
      p = secp256k1_context_create(flags);

      secp256k1_context_set_illegal_callback(
        p, secp256k1_illegal_callback, nullptr);
    }

    ~BCk1Context()
    {
      secp256k1_context_destroy(p);
    }
  };

  using BCk1ContextPtr = std::unique_ptr<BCk1Context>;

  inline BCk1ContextPtr make_bc_context(unsigned int flags)
  {
    return std::make_unique<BCk1Context>(flags);
  }
}