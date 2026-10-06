# SPDX-License-Identifier: BSD-2-Clause
# TA UUID — must match TA_HELLO_WORLD_UUID in ta_hello_world.h
BINARY = b6c53aba-9669-4668-a7f2-205629d16f24

ifdef TA_CROSS_COMPILE
CROSS_COMPILE ?= $(TA_CROSS_COMPILE)
endif
export CROSS_COMPILE

CFG_TEE_TA_LOG_LEVEL ?= 3

-include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

ifeq ($(wildcard $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk),)
clean:
	@echo 'Note: TA_DEV_KIT_DIR not set or missing ta_dev_kit.mk'
endif
