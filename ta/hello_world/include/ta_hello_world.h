/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Vicharak Computers Pvt. Ltd.
 *
 * Hello World TA — minimal TA to verify the TEE plumbing works.
 * UUID: b6c53aba-9669-4668-a7f2-205629d16f24
 */

#ifndef __TA_HELLO_WORLD_H
#define __TA_HELLO_WORLD_H

#define TA_HELLO_WORLD_UUID \
	{ 0xb6c53aba, 0x9669, 0x4668, \
	  { 0xa7, 0xf2, 0x20, 0x56, 0x29, 0xd1, 0x6f, 0x24 } }

/*
 * CMD_HELLO_WORLD
 * No input params.
 * [out] params[0] MEMREF_OUTPUT: buffer to receive the greeting string.
 */
#define CMD_HELLO_WORLD  0x0001

#endif /* __TA_HELLO_WORLD_H */
