#*******************************************************************************
#   Ledger App
#   (c) 2017 Ledger
#   (c) 2019 Haim Bender
#   (c) 2021-2023 Jelurida IP B.V.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#*******************************************************************************

# Enabling DEBUG flag will enable PRINTF and disable optimizations
DEBUG ?= 0

ifeq ($(BOLOS_SDK),)
    $(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.defines

APPNAME = Ardor
APPVERSION_M = 1
APPVERSION_N = 1
APPVERSION_P = 0

DEFINES += APPVERSION_M=$(APPVERSION_M)
DEFINES += APPVERSION_N=$(APPVERSION_N)
DEFINES += APPVERSION_P=$(APPVERSION_P)
APPVERSION = $(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)

VARIANT_PARAM = COIN
VARIANT_VALUES = ardor  

DEFINES += "PATH_PREFIX={44|0x80000000,16754|0x80000000}"
PATH_PREFIX = "44'/16754'"
DEFINES += APP_PREFIX=\"ARDOR-\"

ICON_NANOS = icons/ArdorIconNanoS.gif
ICON_NANOX = icons/ArdorIconNanoX.gif
ICON_NANOSP = icons/ArdorIconNanoX.gif
ICON_STAX = icons/ArdorIcon32px.gif

ENABLE_NBGL_QRCODE = 1

CURVE_APP_LOAD_PARAMS = ed25519
PATH_APP_LOAD_PARAMS = $(PATH_PREFIX)

ENABLE_BLUETOOTH = 1

APP_SOURCE_PATH += src

GEN_TX_TYPE_LIST_SRC := src/txnTypeLists.c

$(GEN_TX_TYPE_LIST_SRC): createTxnTypes.py txtypes.txt
	python3 ./createTxnTypes.py > $@

.PHONY: realclean
realclean: clean
	rm -f $(GEN_TX_TYPE_LIST_SRC)

include $(BOLOS_SDK)/Makefile.standard_app
