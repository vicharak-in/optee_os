// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Vicharak Computers Pvt. Ltd.
 *
 * Vicharak Binary Signing Verification Trusted Application
 * =========================================================
 *
 * Purpose
 * -------
 * Run Vicharak-signed applications only on Vicharak boards, with the trust
 * decision taken inside the TEE. No fuses and no secure boot are required.
 *
 * Security model
 * --------------
 *  - Board identity is derived from the Hardware Unique Key (HUK):
 *    device_id = HMAC(K, "VSAF-device-id-v1"), K from
 *    PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY. It cannot be computed without the HUK.
 *  - At manufacturing Vicharak signs {product, device_id} with the device-CA
 *    key (device certificate). A copied application and certificate fail on
 *    any other board because that board's device_id differs.
 *  - The application is accepted only if its RSA-PSS signature verifies
 *    against the embedded app-signing key. The binary is hashed here, inside
 *    the TEE; no hash supplied by the normal world is ever trusted.
 *  - The returned token = HMAC(K_nonce, binary_hash || device_id || nonce),
 *    K_nonce derived from the HUK and a fresh random nonce, so it is bound to
 *    this board and to this single verification.
 *
 * Limit: without secure boot, someone with root can replace OP-TEE itself.
 * This is a deterrent against copying, not enforcement against a hostile
 * owner of the board.
 */

#include <string.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <pta_system.h>

#include "ta_vicharak_verify.h"
#include "keys_embed.h"

#define LABEL_ID_KEY	"VSAF-device-id-key-v1"
#define LABEL_ID_MAC	"VSAF-device-id-v1"

struct rsa_pub {
	const uint8_t *n;
	size_t n_len;
	const uint8_t *e;
	size_t e_len;
};

struct seg {
	const void *p;
	size_t n;
};

static const struct rsa_pub app_key = {
	vsaf_app_n, sizeof(vsaf_app_n), vsaf_app_e, sizeof(vsaf_app_e)
};
static const struct rsa_pub devca_key = {
	vsaf_devca_n, sizeof(vsaf_devca_n), vsaf_devca_e, sizeof(vsaf_devca_e)
};

static uint32_t rd_le32(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
	       (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint16_t rd_le16(const uint8_t *p)
{
	return (uint16_t)(p[0] | p[1] << 8);
}

static TEE_Result sha256(const void *in, size_t len,
			 uint8_t out[VICHARAK_HASH_SIZE])
{
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	size_t out_len = VICHARAK_HASH_SIZE;
	TEE_Result res = TEE_AllocateOperation(&op, TEE_ALG_SHA256,
					       TEE_MODE_DIGEST, 0);

	if (res)
		return res;
	res = TEE_DigestDoFinal(op, in, len, out, &out_len);
	TEE_FreeOperation(op);
	return res;
}

/* RSA-PSS (SHA-256, MGF1-SHA256, salt 32) verification of a digest. */
static TEE_Result verify_pss_digest(const struct rsa_pub *k,
				    const uint8_t digest[VICHARAK_HASH_SIZE],
				    const uint8_t *sig, size_t sig_len)
{
	TEE_ObjectHandle key = TEE_HANDLE_NULL;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_Attribute attrs[2] = {};
	TEE_Attribute pss = {};
	TEE_Result res = TEE_SUCCESS;

	TEE_InitRefAttribute(&attrs[0], TEE_ATTR_RSA_MODULUS, k->n, k->n_len);
	TEE_InitRefAttribute(&attrs[1], TEE_ATTR_RSA_PUBLIC_EXPONENT,
			     k->e, k->e_len);

	res = TEE_AllocateTransientObject(TEE_TYPE_RSA_PUBLIC_KEY, 2048, &key);
	if (res)
		return res;
	res = TEE_PopulateTransientObject(key, attrs, 2);
	if (res)
		goto out;
	res = TEE_AllocateOperation(&op, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256,
				    TEE_MODE_VERIFY, 2048);
	if (res)
		goto out;
	res = TEE_SetOperationKey(op, key);
	if (res)
		goto out;

	TEE_InitValueAttribute(&pss, TEE_ATTR_RSA_PSS_SALT_LENGTH, 32, 0);
	res = TEE_AsymmetricVerifyDigest(op, &pss, 1, digest,
					 VICHARAK_HASH_SIZE, sig, sig_len);
out:
	if (op != TEE_HANDLE_NULL)
		TEE_FreeOperation(op);
	TEE_FreeTransientObject(key);
	return res;
}

/* Key bound to this board (HUK) and this TA, diversified by `extra`. */
static TEE_Result derive_key(const void *extra, size_t extra_len,
			     uint8_t out[32])
{
	TEE_UUID uuid = PTA_SYSTEM_UUID;
	TEE_TASessionHandle sess = TEE_HANDLE_NULL;
	TEE_Param p[TEE_NUM_PARAMS] = {};
	uint32_t origin = 0;
	uint32_t pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				      TEE_PARAM_TYPE_MEMREF_OUTPUT,
				      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	TEE_Result res = TEE_OpenTASession(&uuid, TEE_TIMEOUT_INFINITE, 0,
					   NULL, &sess, &origin);

	if (res) {
		EMSG("VICHARAK: open system PTA failed: 0x%x", res);
		return res;
	}
	p[0].memref.buffer = (void *)extra;
	p[0].memref.size = extra_len;
	p[1].memref.buffer = out;
	p[1].memref.size = 32;
	res = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE,
				  PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY, pt, p,
				  &origin);
	TEE_CloseTASession(sess);
	if (res)
		EMSG("VICHARAK: derive key failed: 0x%x", res);
	return res;
}

static TEE_Result hmac_sha256(const uint8_t key[32], const struct seg *segs,
			      size_t nsegs, uint8_t out[32])
{
	TEE_ObjectHandle k = TEE_HANDLE_NULL;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_Attribute attr = {};
	size_t out_len = 32;
	TEE_Result res = TEE_SUCCESS;
	size_t i = 0;

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, 32);
	res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, 256, &k);
	if (res)
		return res;
	res = TEE_PopulateTransientObject(k, &attr, 1);
	if (res)
		goto out;
	res = TEE_AllocateOperation(&op, TEE_ALG_HMAC_SHA256, TEE_MODE_MAC, 256);
	if (res)
		goto out;
	res = TEE_SetOperationKey(op, k);
	if (res)
		goto out;

	TEE_MACInit(op, NULL, 0);
	for (i = 0; i + 1 < nsegs; i++)
		TEE_MACUpdate(op, segs[i].p, segs[i].n);
	res = TEE_MACComputeFinal(op, segs[nsegs - 1].p, segs[nsegs - 1].n,
				  out, &out_len);
out:
	if (op != TEE_HANDLE_NULL)
		TEE_FreeOperation(op);
	TEE_FreeTransientObject(k);
	return res;
}

static TEE_Result compute_device_id(uint8_t id[VICHARAK_DEVICE_ID_SIZE])
{
	const struct seg msg = { LABEL_ID_MAC, sizeof(LABEL_ID_MAC) - 1 };
	uint8_t k[32] = {};
	TEE_Result res = derive_key(LABEL_ID_KEY, sizeof(LABEL_ID_KEY) - 1, k);

	if (!res)
		res = hmac_sha256(k, &msg, 1, id);
	TEE_MemFill(k, 0, sizeof(k));
	return res;
}

/*
 * Check the device certificate: signed by the device-CA key, well formed, and
 * issued for THIS board's device ID. Constant-time compare on the ID.
 */
static TEE_Result verify_device_cert(const uint8_t cert[VSAF_DEVCERT_SIZE],
				     const uint8_t id[VICHARAK_DEVICE_ID_SIZE])
{
	const uint8_t *body = cert;
	const uint8_t *sig = cert + VSAF_DEVCERT_BODY_SIZE;
	uint8_t digest[VICHARAK_HASH_SIZE] = {};
	TEE_Result res = sha256(body, VSAF_DEVCERT_BODY_SIZE, digest);

	if (res)
		return res;
	if (verify_pss_digest(&devca_key, digest, sig, VICHARAK_SIG_SIZE)) {
		EMSG("VICHARAK: device certificate signature invalid");
		return TEE_ERROR_SECURITY;
	}
	if (rd_le32(body) != VSAF_DEVCERT_MAGIC ||
	    rd_le16(body + 4) != VSAF_DEVCERT_VERSION ||
	    rd_le16(body + 6) != VICHARAK_DEVICE_ID_SIZE) {
		EMSG("VICHARAK: device certificate malformed");
		return TEE_ERROR_SECURITY;
	}
	if (TEE_MemCompare(body + 12, id, VICHARAK_DEVICE_ID_SIZE)) {
		EMSG("VICHARAK: device certificate is for a different board");
		return TEE_ERROR_SECURITY;
	}
	return TEE_SUCCESS;
}

/*
 * token = HMAC(K_nonce, binary_hash || device_id || nonce), K_nonce derived
 * from the HUK and the nonce. Shared by issuing and checking so they cannot
 * disagree.
 */
static TEE_Result compute_token(const uint8_t hash[VICHARAK_HASH_SIZE],
				const uint8_t id[VICHARAK_DEVICE_ID_SIZE],
				const uint8_t nonce[VICHARAK_NONCE_SIZE],
				uint8_t token[VICHARAK_TOKEN_SIZE])
{
	struct seg segs[3] = {};
	uint8_t kt[32] = {};
	TEE_Result res = derive_key(nonce, VICHARAK_NONCE_SIZE, kt);

	if (res)
		return res;
	segs[0].p = hash;  segs[0].n = VICHARAK_HASH_SIZE;
	segs[1].p = id;    segs[1].n = VICHARAK_DEVICE_ID_SIZE;
	segs[2].p = nonce; segs[2].n = VICHARAK_NONCE_SIZE;
	res = hmac_sha256(kt, segs, 3, token);
	TEE_MemFill(kt, 0, sizeof(kt));
	return res;
}

static TEE_Result cmd_get_device_id(uint32_t param_types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t id[VICHARAK_DEVICE_ID_SIZE] = {};
	TEE_Result res = TEE_SUCCESS;

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;
	if (params[0].memref.size < VICHARAK_DEVICE_ID_SIZE) {
		params[0].memref.size = VICHARAK_DEVICE_ID_SIZE;
		return TEE_ERROR_SHORT_BUFFER;
	}

	res = compute_device_id(id);
	if (res)
		return res;
	TEE_MemMove(params[0].memref.buffer, id, sizeof(id));
	params[0].memref.size = sizeof(id);
	return TEE_SUCCESS;
}

static TEE_Result cmd_verify_binary(uint32_t param_types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT);
	uint8_t auth[VICHARAK_AUTH_SIZE] = {};
	uint8_t id[VICHARAK_DEVICE_ID_SIZE] = {};
	uint8_t hash[VICHARAK_HASH_SIZE] = {};
	uint8_t nonce[VICHARAK_NONCE_SIZE] = {};
	uint8_t token[VICHARAK_TOKEN_SIZE] = {};
	TEE_Result res = TEE_SUCCESS;

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!params[0].memref.size ||
	    params[1].memref.size != VICHARAK_AUTH_SIZE ||
	    params[2].memref.size < VICHARAK_TOKEN_SIZE ||
	    params[3].memref.size < VICHARAK_NONCE_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Copy the untrusted bundle once; never re-read shared memory. */
	TEE_MemMove(auth, params[1].memref.buffer, sizeof(auth));

	res = compute_device_id(id);
	if (res)
		goto out;
	res = verify_device_cert(auth + VICHARAK_SIG_SIZE, id);
	if (res)
		goto out;

	res = sha256(params[0].memref.buffer, params[0].memref.size, hash);
	if (res)
		goto out;
	if (verify_pss_digest(&app_key, hash, auth, VICHARAK_SIG_SIZE)) {
		EMSG("VICHARAK: application signature invalid");
		res = TEE_ERROR_SECURITY;
		goto out;
	}

	TEE_GenerateRandom(nonce, sizeof(nonce));
	res = compute_token(hash, id, nonce, token);
	if (res)
		goto out;

	TEE_MemMove(params[2].memref.buffer, token, sizeof(token));
	TEE_MemMove(params[3].memref.buffer, nonce, sizeof(nonce));
	params[2].memref.size = sizeof(token);
	params[3].memref.size = sizeof(nonce);
	IMSG("VICHARAK: application verified for this board");
out:
	TEE_MemFill(token, 0, sizeof(token));
	return res;
}

static TEE_Result cmd_verify_token(uint32_t param_types,
				   TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	uint8_t given[VICHARAK_TOKEN_SIZE + VICHARAK_NONCE_SIZE] = {};
	uint8_t id[VICHARAK_DEVICE_ID_SIZE] = {};
	uint8_t hash[VICHARAK_HASH_SIZE] = {};
	uint8_t expect[VICHARAK_TOKEN_SIZE] = {};
	TEE_Result res = TEE_SUCCESS;

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!params[0].memref.size ||
	    params[1].memref.size != sizeof(given))
		return TEE_ERROR_BAD_PARAMETERS;

	/* Copy the untrusted token once; never re-read shared memory. */
	TEE_MemMove(given, params[1].memref.buffer, sizeof(given));

	res = compute_device_id(id);
	if (res)
		goto out;
	res = sha256(params[0].memref.buffer, params[0].memref.size, hash);
	if (res)
		goto out;
	res = compute_token(hash, id, given + VICHARAK_TOKEN_SIZE, expect);
	if (res)
		goto out;

	if (TEE_MemCompare(expect, given, VICHARAK_TOKEN_SIZE)) {
		EMSG("VICHARAK: token does not match this binary on this board");
		res = TEE_ERROR_SECURITY;
	}
out:
	TEE_MemFill(expect, 0, sizeof(expect));
	return res;
}

/* =====================  GP TEE TA entry points  ===================== */

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types __unused,
				    TEE_Param params[4] __unused,
				    void **sess_ctx __unused)
{
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx __unused)
{
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx __unused,
				      uint32_t cmd_id, uint32_t param_types,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case CMD_GET_DEVICE_ID:
		return cmd_get_device_id(param_types, params);
	case CMD_VERIFY_BINARY:
		return cmd_verify_binary(param_types, params);
	case CMD_VERIFY_TOKEN:
		return cmd_verify_token(param_types, params);
	default:
		EMSG("VICHARAK: unknown command 0x%x", cmd_id);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
