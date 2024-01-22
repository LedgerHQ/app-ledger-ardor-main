/*******************************************************************************
 *  (c) 2019 Haim Bender
 *  (c) 2021-2023 Jelurida IP B.V.
 *
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#pragma once

// This is the header for different types of consts and configurations, the actual values are set in
// config.c

typedef struct {
    uint32_t chainId;
    const char* name;
    uint8_t numDecimalsBeforePoint;
} chainType;

typedef struct {
    const char* name;
} appendageType;

extern const chainType CHAINS[];
extern const uint8_t NUM_CHAINS;
extern const uint8_t SUPPORTED_TXN_VERSION;
extern const appendageType APPENDAGE_TYPES[];
extern const uint8_t NUM_APPENDAGE_TYPES;

extern const uint8_t ARDOR_SPECIAL_IDENTIFIER[];
extern const uint8_t ARDOR_SPECIAL_IDENTIFIER_LEN;

extern const uint16_t VERSION;
extern const uint8_t VERSION_FLAGS;

#define ARRAY_COUNT(array) (sizeof(array) / sizeof(array[0]))

#define MIN_DERIVATION_LENGTH 3
#define MAX_DERIVATION_LENGTH 20

#define PUBLIC_KEY_SIZE 32
#define SIGNATURE_SIZE 64
#define TIMESTAMP_SIZE 4

#define FUNCTION_STACK_SIZE 30
#define BASE_TRANSACTION_SIZE 145

// transaction types and subtypes definition
// note: you have to write the type and subtype in reverse, because of little endian buffer
// representation an big endian C code representation
#define TX_TYPE_ORDINARY_PAYMENT 0x0000
#define TX_TYPE_FXT_PAYMENT 0x00fe
#define TX_TYPE_FXT_COIN_EXCHANGE_ORDER_ISSUE 0x00fc
#define TX_TYPE_COIN_EXCHANGE_ORDER_ISSUE 0x000b
#define TX_TYPE_ASK_ORDER_PLACEMENT 0x0202
#define TX_TYPE_BID_ORDER_PLACEMENT 0x0302
#define TX_TYPE_ASSET_TRANSFER 0x0102
