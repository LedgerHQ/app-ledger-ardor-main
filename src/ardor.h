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

#include "cx.h"
#include "os.h"
#include "config.h"

cx_err_t publicKeyToId(const uint8_t* const publicKey, uint64_t* const accountIdOut);

uint8_t ardorKeys(const uint8_t* const derivationPath,
                  const uint8_t derivationPathLengthInUints32,
                  uint8_t* const keySeedBfrOut,
                  uint8_t* const publicKeyCurveXout,
                  uint8_t* const publicKeyEd25519YLEWithXParityOut,
                  uint8_t* const chainCodeOut,
                  uint16_t* const exceptionOut);

bool isValidDerivationPathLength(uint8_t derivationPathLengthInUints32);

char* chainName(const uint8_t chainId);

cx_err_t signMsg(uint8_t* const keySeedBfr, const uint8_t* const msgSha256, uint8_t* const sig);

bool check_canary();

uint8_t getSharedEncryptionKey(const uint8_t* const derivationPath,
                               const uint8_t derivationPathLengthInUints32,
                               const uint8_t* const targetPublicKey,
                               const uint8_t* const nonce,
                               uint16_t* const exceptionOut,
                               uint8_t* const aesKeyOut);

// the amount of digits on the right of the decimal dot for each chain
uint8_t chainNumDecimalsBeforePoint(const uint8_t chainId);

uint8_t formatAmount(char* const outputString,
                     const uint16_t maxOutputLength,
                     uint64_t numberToFormat,
                     const uint8_t numDigitsBeforeDecimal);

uint8_t formatChainAmount(char* const out,
                          const uint16_t maxLength,
                          uint64_t amount,
                          const uint8_t chainId);

void cleanState();

// define max text sizes for the different UI screens

// 9,223,372,036,854,775,807 is the biggest number you can hold in uint64 + the dot + null
#define MAX_FEE_TEXT_SIZE 21
#define MAX_CHAIN_AND_TXN_TYPE_TEXT_SIZE 60
#define MAX_WINDOWS 3             // Additional windows, depending on the txn type
#define MAX_WINDOW_TITLE_SIZE 20  // The longest string is price per (chain name here)
#define MAX_WINDOW_TEXT_SIZE 31   // MAX(Ardor arddress = 27, feeText + chainName)
// this should allow displaying the names for up to three types, otherwise we show a bitmap
#define MAX_APPENDAGES_TEXT_SIZE 60

enum authTxnStates { AUTH_STATE_INIT, AUTH_STATE_PARSING, AUTH_STATE_USER_AUTHORIZED };

// This is the state object that authAndSignTxn uses
typedef struct {
    enum authTxnStates state;
    bool requiresBlindSigning;  // This is true if the TX is a blind signing TX

    uint8_t readBuffer[512];        // This is where unparsed temp buffer data is kept, since we do
                                    // streamed parsing we have to have it here
    uint16_t readBufferEndPos;      // Index of the last byte in readBuffer
    uint16_t readBufferReadOffset;  // Index of the first byte in readBuffer
    uint16_t numBytesRead;          // The total number of bytes parsed up until now

    uint8_t functionStack[FUNCTION_STACK_SIZE];  // This is stack of all the function that have yet
                                                 // to parse the TXN, the C handler file explains
                                                 // this process in more detail
    uint8_t numFunctionsOnStack;

    cx_sha256_t hashstate;  // The state of the hash for the txn buffer

    uint32_t chainId;
    uint16_t txnTypeAndSubType;
    uint8_t txnTypeIndex;  // txnTypeAndSubType's index in TXN_TYPES

    uint64_t recipientId;  // the recipient address ID
    uint64_t amount;  // the amount to be sent in the txn, note that every chain parses this number
                      // differently, it divides this number by some 10^X
    uint64_t fee;

    // Different attachments have different payloads. Each transaction type & subtype have
    // a specific attachment. We use a union to define each supported attachment to preserve storage
    union {
        struct {
            uint32_t chainId;
            uint32_t exchangeChainId;
            uint64_t quantityQNT;
            uint64_t priceNQT;
        } coinExchange;
        struct {
            uint64_t assetId;
            uint64_t quantityQNT;
            uint64_t priceNQT;
        } assetOrderPlacement;
        struct {
            uint64_t assetId;
            uint64_t quantityQNT;
        } assetTransfer;
    } attachment;

    uint16_t txnSizeBytes;  // The declared Txn size

    char feeText[MAX_FEE_TEXT_SIZE];
    char chainAndTxnTypeText[MAX_CHAIN_AND_TXN_TYPE_TEXT_SIZE];
    // additional UI screens, depending on the txn type
    char windowTitles[MAX_WINDOWS][MAX_WINDOW_TITLE_SIZE];
    char windowTexts[MAX_WINDOWS][MAX_WINDOW_TEXT_SIZE];
    char appendagesText[MAX_APPENDAGES_TEXT_SIZE];
} authTxn_t;

#define MAX_CHUNK_SIZE_ENCRYPT 224

// State for the encryptDecrypt handler
typedef struct {
    uint8_t mode;                                // Modes are described in the .C file
    uint8_t cbc[CX_AES_BLOCK_SIZE];              // Something to do with AES state
    cx_aes_key_t aesKey;                         // This is the encryption key
    uint8_t buffer[MAX_CHUNK_SIZE_ENCRYPT + 1];  // +1 for R_SUCCESS at position 0
} encryptionState_t;

enum signTokenStates { SIGN_TOKEN_UNINIT, SIGN_TOKEN_INIT, SIGN_TOKEN_BYTES_RECEIVED };

// 100-byte token consists of a 32-byte public key, a 4-byte timestamp, and a 64-byte signature
#define TOKEN_SIZE (1 + PUBLIC_KEY_SIZE + TIMESTAMP_SIZE + SIGNATURE_SIZE)

// State of the sign token handler
typedef struct {
    enum signTokenStates state;             // The state of the handler
    cx_sha256_t sha256;                     // The state of the token hash
    uint32_t timestamp;                     // The timestamp of the token
    uint8_t derivationPathLengthInUints32;  // The length of the derivation path
    uint8_t* ptrDerivationPath;             // The derivation path
    uint8_t token[TOKEN_SIZE];              // The 1 byte response code + token
} signTokenState_t;

// This is the states type, the actual object is defined in ardor.c
typedef struct {
    encryptionState_t encryption;
    authTxn_t txnAuth;
    signTokenState_t tokenSign;
} states_t;

// declared in ardor.c
extern states_t state;

// Settings
typedef struct {
    bool allowBlindSigning;
} settings_t;

typedef struct internalStorage_t {
    settings_t settings;
    bool initialized;
} internalStorage_t;

extern const internalStorage_t N_storage_real;
#define N_storage (*(volatile internalStorage_t*) PIC(&N_storage_real))

// used to list txn types
typedef struct {
    uint16_t id;
    const char* name;
    uint8_t attachmentParsingFunctionNumber;
} txnType;

// These to are automaticly generated by createTxnTypes.py into src/txnTypeLists.c
extern const txnType TXN_TYPES[];
extern const uint8_t LEN_TXN_TYPES;

// These are the offsets of various parts of a request APDU packet. INS
// identifies the requested command (see above), and P1 and P2 are parameters
// to the command.
#define CLA 0xE0
#define OFFSET_CLA 0x00
#define OFFSET_INS 0x01
#define OFFSET_P1 0x02
#define OFFSET_P2 0x03
#define OFFSET_LC 0x04
#define OFFSET_CDATA 0x05
