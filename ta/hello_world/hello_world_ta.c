// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Vicharak Computers Pvt. Ltd.
 *
 * Hello World Trusted Application.
 *
 * The simplest possible TA: one command that copies a greeting string
 * into the caller's output buffer and returns TEE_SUCCESS.
 *
 * This TA exists purely to confirm:
 *   1. tee-supplicant can load and verify the .ta binary.
 *   2. A CA can open a TEE session.
 *   3. A command invocation round-trips successfully.
 */

#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "ta_hello_world.h"

static const char greeting[] = "Hello from the Vicharak TEE! OP-TEE is alive.";

/* ── GP entry points ────────────────────────────────────────────────────── */

TEE_Result TA_CreateEntryPoint(void)
{
	IMSG("hello_world: TA created");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	IMSG("hello_world: TA destroyed");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types __unused,
				    TEE_Param params[4]   __unused,
				    void **sess_ctx       __unused)
{
	IMSG("hello_world: session opened");
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx __unused)
{
	IMSG("hello_world: session closed");
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx    __unused,
				      uint32_t cmd_id,
				      uint32_t param_types,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	if (cmd_id != CMD_HELLO_WORLD) {
		EMSG("hello_world: unknown command 0x%x", cmd_id);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	const uint32_t exp_pt =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);

	if (param_types != exp_pt) {
		EMSG("hello_world: bad param types 0x%x", param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	size_t greeting_len = sizeof(greeting); /* includes NUL */

	if (params[0].memref.size < greeting_len) {
		params[0].memref.size = greeting_len;
		return TEE_ERROR_SHORT_BUFFER;
	}

	TEE_MemMove(params[0].memref.buffer, greeting, greeting_len);
	params[0].memref.size = greeting_len;

	IMSG("hello_world: said hello to normal world");
	return TEE_SUCCESS;
}
