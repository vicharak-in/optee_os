/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Vicharak Computers Pvt. Ltd.
 */

#ifndef __USER_TA_HEADER_DEFINES_H
#define __USER_TA_HEADER_DEFINES_H

#include <ta_vicharak_verify.h>

#define TA_UUID			TA_VICHARAK_VERIFY_UUID

/*
 * TA_FLAG_SINGLE_INSTANCE: only one instance runs at a time (state is
 * shared across sessions — correct here since we have no mutable state).
 * TA_FLAG_MULTI_SESSION: allow multiple callers to open sessions
 * concurrently.
 */
#define TA_FLAGS		(TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION)

/*
 * Stack: RSA-2048 key import + HMAC state fits in 16 KB.
 * Heap:  temporary binary-hash + signature buffers, 32 KB is plenty
 *        for the small binaries targeted by this TA.
 */
#define TA_STACK_SIZE		(32 * 1024)
#define TA_DATA_SIZE		(32 * 1024)

#define TA_VERSION		"1.0.0"
#define TA_DESCRIPTION		"Vicharak Binary Signing Verification TA"

#endif /* __USER_TA_HEADER_DEFINES_H */
