/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Vicharak Computers Pvt. Ltd.
 *
 * Shared header between the Trusted Application, the Client Application and
 * the host tools (tools/vsaf_devcert.py). Defines the TA UUID, the command
 * interface and the device-certificate layout.
 */

#ifndef __TA_VICHARAK_VERIFY_H
#define __TA_VICHARAK_VERIFY_H

/*
 * Trusted Application UUID:
 *   a3f1c2d4-5b6e-7f80-91a2-b3c4d5e6f708
 *
 * Generated once; must match the TA binary filename and TEEC_UUID in the CA.
 */
#define TA_VICHARAK_VERIFY_UUID \
	{ 0xa3f1c2d4, 0x5b6e, 0x7f80, \
	  { 0x91, 0xa2, 0xb3, 0xc4, 0xd5, 0xe6, 0xf7, 0x08 } }

/*
 * CMD_GET_DEVICE_ID - Return this board's device ID.
 *
 * device_id = HMAC-SHA256(K, "VSAF-device-id-v1") where K is derived from the
 * Hardware Unique Key through PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY. It is unique
 * per board, cannot be computed without the HUK, and reveals nothing about K.
 * The manufacturing station reads it and has Vicharak sign it (device cert).
 *
 * [out]  params[0]  MEMREF_OUTPUT  : device ID (32 bytes)
 */
#define CMD_GET_DEVICE_ID	0x0002

/*
 * CMD_VERIFY_BINARY - Verify a signed application on this specific board.
 *
 * Inside the secure world the TA:
 *   1. recomputes this board's device ID;
 *   2. verifies the device certificate with the embedded device-CA key and
 *      checks that the ID in it equals step 1 (constant-time compare);
 *   3. hashes the application binary itself (the hash never comes from the
 *      normal world);
 *   4. verifies the application signature with the embedded app-signing key;
 *   5. returns token = HMAC-SHA256(K_nonce, binary_hash || device_id || nonce)
 *      with K_nonce derived from the HUK and a fresh random nonce.
 *
 * Any failure returns TEE_ERROR_SECURITY and no token.
 *
 * [in]   params[0]  MEMREF_INPUT   : application binary
 * [in]   params[1]  MEMREF_INPUT   : auth bundle = app signature (256 bytes)
 *                                    followed by the device certificate
 *                                    (VICHARAK_AUTH_SIZE bytes in total)
 * [out]  params[2]  MEMREF_OUTPUT  : session token (32 bytes)
 * [out]  params[3]  MEMREF_OUTPUT  : nonce (32 bytes)
 */
#define CMD_VERIFY_BINARY	0x0001

/*
 * CMD_VERIFY_TOKEN - Called by the application itself to prove that the token
 * it was launched with is genuine for this binary on this board.
 *
 * The TA hashes the supplied bytes, recomputes
 *   HMAC(K_nonce, binary_hash || device_id || nonce)
 * with K_nonce derived from the HUK and the supplied nonce, and compares it
 * with the supplied token in constant time. Only a TEE holding this board's
 * HUK can produce a matching token, so random bytes, a token from another
 * board, or a token issued for a different binary all fail.
 *
 * Limit: the TA keeps no state, so a genuine token+nonce captured once can be
 * replayed for the same binary on the same board. The caller also chooses
 * which bytes to present; real caller identity needs help from the OS.
 *
 * [in]   params[0]  MEMREF_INPUT   : the application binary (its own bytes)
 * [in]   params[1]  MEMREF_INPUT   : token (32 bytes) || nonce (32 bytes)
 *
 * Returns TEE_SUCCESS, or TEE_ERROR_SECURITY if the token does not match.
 */
#define CMD_VERIFY_TOKEN	0x0003

/* Size constants shared between TA, CA and tools */
#define VICHARAK_SIG_SIZE	256	/* RSA-2048 signature length in bytes */
#define VICHARAK_TOKEN_SIZE	32	/* HMAC-SHA256 output */
#define VICHARAK_NONCE_SIZE	32	/* Random nonce */
#define VICHARAK_HASH_SIZE	32	/* SHA-256 digest */
#define VICHARAK_DEVICE_ID_SIZE	32	/* HMAC-SHA256 output */

/*
 * Device certificate = body || RSA-PSS-SHA256 signature (salt 32) over body,
 * signed by the Vicharak device-CA key at manufacturing. Body, little endian:
 *
 *   off  size  field
 *     0     4  magic      0x43445356 ("VSDC" in file byte order)
 *     4     2  version    1
 *     6     2  id_len     32
 *     8     4  product    four ASCII bytes, e.g. "AXON"
 *    12    32  device_id
 */
#define VSAF_DEVCERT_MAGIC	0x43445356u
#define VSAF_DEVCERT_VERSION	1
#define VSAF_DEVCERT_BODY_SIZE	44
#define VSAF_DEVCERT_SIZE	(VSAF_DEVCERT_BODY_SIZE + VICHARAK_SIG_SIZE)
#define VICHARAK_AUTH_SIZE	(VICHARAK_SIG_SIZE + VSAF_DEVCERT_SIZE)

#endif /* __TA_VICHARAK_VERIFY_H */
