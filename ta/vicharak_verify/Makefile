# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026, Vicharak Computers Pvt. Ltd.
#
# TA UUID — must match TA_VICHARAK_VERIFY_UUID in ta_vicharak_verify.h
BINARY = a3f1c2d4-5b6e-7f80-91a2-b3c4d5e6f708

ifdef TA_CROSS_COMPILE
CROSS_COMPILE ?= $(TA_CROSS_COMPILE)
endif
export CROSS_COMPILE

# Log level: 2 = IMSG/EMSG only (appropriate for production)
CFG_TEE_TA_LOG_LEVEL ?= 2
CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)

-include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

ifeq ($(wildcard $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk),)
clean:
	@echo 'Note: $$(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk not found, cannot clean TA'
	@echo 'Note: TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)'
endif
