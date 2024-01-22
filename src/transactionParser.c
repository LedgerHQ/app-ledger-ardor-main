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

#include <string.h>

#include "ardor.h"
#include "returnValues.h"
#include "transactionParser.h"

#define TX_TIMESTAMP_DEADLINE 2

// returns the txn type at the given index
static txnType* txnTypeAtIndex(const uint8_t index) {
    return (txnType*) PIC(&TXN_TYPES[index]);
}

// returns the txn type name at the given index
static char* txnTypeNameAtIndex(const uint8_t index) {
    return (char*) PIC(((txnType*) PIC(&TXN_TYPES[index]))->name);
}

/**
 * Returns the index of the transaction type in the array of transaction types.
 *
 * @param txnTypeAndSubType The transaction type and subtype combined into a single uint16_t value.
 * @return The index of the transaction type in the array of transaction types.
 */
static uint8_t getTransactionTypeIndex(uint16_t txnTypeAndSubType) {
    uint8_t index = 0;
    while (index < LEN_TXN_TYPES) {
        if (txnTypeAtIndex(index)->id == txnTypeAndSubType) {
            break;
        }
        index++;
    }
    return index;
}

/**
 * Checks if the given transaction type is a payment transaction type.
 *
 * @param txTypeAndSub The transaction type and subtype to check.
 * @return true if the transaction type is a payment transaction type, false otherwise.
 */
static bool isPaymentTxType(uint16_t txTypeAndSub) {
    return txTypeAndSub == TX_TYPE_ORDINARY_PAYMENT || txTypeAndSub == TX_TYPE_FXT_PAYMENT;
}

static char* appendageTypeName(const uint8_t index) {
    return (char*) PIC(((appendageType*) PIC(&APPENDAGE_TYPES[index]))->name);
}

// note: ardor chain index starts with index 1
static bool isValidChainId(uint32_t chainId) {
    return chainId > 0 && chainId <= NUM_CHAINS;
}

// adds a parsing function to the top of the stack
static uint8_t addToFunctionStack(const uint8_t functionNum) {
    if (state.txnAuth.numFunctionsOnStack == sizeof(state.txnAuth.functionStack)) {
        return R_FUNCTION_STACK_FULL;
    }

    state.txnAuth.functionStack[state.txnAuth.numFunctionsOnStack++] = functionNum;

    return R_SUCCESS;
}

// Takes bytes away from the buffer, returns 0 if there aren't enough bytes
static uint8_t* readFromBuffer(const uint8_t size) {
    if (size > state.txnAuth.readBufferEndPos - state.txnAuth.readBufferReadOffset) {
        return 0;
    }

    uint8_t* ret = state.txnAuth.readBuffer + state.txnAuth.readBufferReadOffset;
    state.txnAuth.readBufferReadOffset += size;
    state.txnAuth.numBytesRead += size;

    return ret;
}

/**
 * @brief Prints the transaction type text.
 *
 * This function prints the transaction type text consisting on the the chain name and the
 * transaction type name.
 * In case of unknown transactions it prints "UnknownTxnType" and signals blind signing.
 *
 * @return void
 */
static void printTxnTypeText() {
    if (state.txnAuth.txnTypeIndex < LEN_TXN_TYPES) {
        snprintf(state.txnAuth.chainAndTxnTypeText,
                 sizeof(state.txnAuth.chainAndTxnTypeText),
                 "%s\n%s",
                 chainName(state.txnAuth.chainId),
                 txnTypeNameAtIndex(state.txnAuth.txnTypeIndex));
    } else {
        snprintf(state.txnAuth.chainAndTxnTypeText,
                 sizeof(state.txnAuth.chainAndTxnTypeText),
                 "%s\nUnknownTxnType",
                 chainName(state.txnAuth.chainId));
        state.txnAuth.requiresBlindSigning = true;
    }
}

/**
 * Formats and prints the fee amount and chain name (which acts as token name) to the state.
 *
 * @param fee The fee amount to be formatted and printed.
 * @return Returns true if the fee text was successfully printed, false otherwise.
 */
static bool printFeeText(uint64_t fee) {
    uint8_t ret = formatAmount(state.txnAuth.feeText,
                               sizeof(state.txnAuth.feeText),
                               fee,
                               chainNumDecimalsBeforePoint(state.txnAuth.chainId));

    if (ret == 0) {
        return false;
    }

    snprintf(state.txnAuth.feeText + ret - 1,
             sizeof(state.txnAuth.feeText) - ret - 1,
             " %s",
             chainName(state.txnAuth.chainId));

    return true;
}

// PARSE_FN_MAIN 1
// This is the main parse function, it parses the main tx body and adds more functions to the parse
// stack if needed
static uint8_t parseMainTxnData() {
    uint8_t* ptr = readFromBuffer(BASE_TRANSACTION_SIZE);

    if (ptr == 0) {
        return R_SEND_MORE_BYTES;
    }

    memmove(&(state.txnAuth.chainId), ptr, sizeof(state.txnAuth.chainId));

    ptr += sizeof(state.txnAuth.chainId);

    if (!isValidChainId(state.txnAuth.chainId)) {
        return R_BAD_CHAIN_ID_ERR;
    }

    memmove(&(state.txnAuth.txnTypeAndSubType), ptr, sizeof(state.txnAuth.txnTypeAndSubType));

    ptr += sizeof(state.txnAuth.txnTypeAndSubType);

    state.txnAuth.txnTypeIndex = getTransactionTypeIndex(state.txnAuth.txnTypeAndSubType);
    txnType* txType =
        state.txnAuth.txnTypeIndex < LEN_TXN_TYPES ? txnTypeAtIndex(state.txnAuth.txnTypeIndex) : 0;

    if (state.txnAuth.txnTypeIndex < LEN_TXN_TYPES &&
        txType->attachmentParsingFunctionNumber != 0) {
        addToFunctionStack(txType->attachmentParsingFunctionNumber);
    }

    // general blind signing check, functions without specific parsing are marked as blind signing
    // except payments which don't require special parsing
    if (state.txnAuth.txnTypeIndex >= LEN_TXN_TYPES ||
        (txType->attachmentParsingFunctionNumber == 0 &&
         !isPaymentTxType(state.txnAuth.txnTypeAndSubType))) {
        state.txnAuth.requiresBlindSigning = true;
    }

    printTxnTypeText();

    if (*((uint8_t*) ptr) != SUPPORTED_TXN_VERSION) {
        return R_WRONG_VERSION_ERR;
    }
    ptr += sizeof(uint8_t);  // version

    ptr += TIMESTAMP_SIZE;         // Skip the timestamp
    ptr += TX_TIMESTAMP_DEADLINE;  // Skip the deadline
    ptr += PUBLIC_KEY_SIZE;        // Skip the sender publickey

    memmove(&(state.txnAuth.recipientId), ptr, sizeof(state.txnAuth.recipientId));
    ptr += sizeof(state.txnAuth.recipientId);

    memmove(&(state.txnAuth.amount), ptr, sizeof(state.txnAuth.amount));
    ptr += sizeof(state.txnAuth.amount);

    uint64_t fee = 0;
    memmove(&fee, ptr, sizeof(fee));
    if (!printFeeText(fee)) {
        return R_FORMAT_FEE_ERR;
    }

    addToFunctionStack(PARSE_FN_IGNORE_BYTES_UNTIL_THE_END);

    return R_SUCCESS;
}

// PARSE_FN_APPENDAGES_FLAGS 2
/**
 * Parses the appendage type flag and prepares the text to show the user.
 * This function is added to the function stack on init.
 *
 * Current known appendages types:
 *      MessageAppendix = 1
 *      EncryptedMessageAppendix = 2
 *      EncryptToSelfMessageAppendix = 4
 *      PrunablePlainMessageAppendix = 8
 *      PrunableEncryptedMessageAppendix = 16
 *      PublicKeyAnnouncementAppendix = 32
 *      PhasingAppendix = 64
 */
static uint8_t parseAppendagesFlags() {
    uint8_t* buffPtr = readFromBuffer(sizeof(uint32_t));

    if (buffPtr == 0) {
        return R_SEND_MORE_BYTES;
    }

    uint32_t appendages = 0;

    memmove(&appendages, buffPtr, sizeof(appendages));

    if (appendages != 0) {
        state.txnAuth.requiresBlindSigning = true;

        // fallback to hex string if we found unknown appendages
        if (appendages >= 1 << NUM_APPENDAGE_TYPES) {
            snprintf(state.txnAuth.appendagesText,
                     sizeof(state.txnAuth.appendagesText),
                     "0x%08X",
                     appendages);
        } else {
            char* ptr = state.txnAuth.appendagesText;
            size_t free = sizeof(state.txnAuth.appendagesText);
            for (uint8_t j = 0; j < NUM_APPENDAGE_TYPES; j++) {
                if ((appendages & 1 << j) != 0) {
                    size_t len = strlen(appendageTypeName(j));

                    // special case: not enough space to show the text for all appendages, revert to
                    // bitmap
                    if (len + 2 > free) {  // +2 for separator and null terminator
                        int limit = MIN(NUM_APPENDAGE_TYPES, free - 1);  // security audit
                        for (uint8_t i = 0; i < limit; i++) {
                            state.txnAuth.appendagesText[i] =
                                (appendages & 1 << i) != 0 ? '1' + i : '_';
                        }
                        state.txnAuth.appendagesText[limit] = '\0';
                        return R_SUCCESS;
                    }

                    snprintf(ptr,
                             free,
                             ptr == state.txnAuth.appendagesText ? "%s" : "\n%s",
                             appendageTypeName(j));
                    ptr += ptr == state.txnAuth.appendagesText ? len : len + 1;
                    free -= ptr == state.txnAuth.appendagesText ? len : len + 1;
                }
            }
        }
    }

    return R_SUCCESS;
}

// PARSE_FN_FXT_COIN_EXCHANGE_ORDER_ISSUE_OR_COIN_EXCHANGE_ORDER_ISSUE_ATTACHMENT 4
// Parses a specific type of attachment
static uint8_t parseFxtCoinExchangeOrderIssueOrCoinExchangeOrderIssueAttachment() {
    uint32_t chainId = 0;          // chainId
    uint32_t exchangeChainId = 0;  // exchangeChain
    uint64_t quantityQNT = 0;      // quantity
    uint64_t priceNQT = 0;         // price

    uint8_t* ptr = readFromBuffer(sizeof(uint8_t) + sizeof(state.txnAuth.attachment.coinExchange));
    if (ptr == 0) {
        return R_SEND_MORE_BYTES;
    }

    if (*ptr != 1) {
        return R_UNSUPPORTED_ATTACHMENT_VERSION;
    }

    ptr += 1;  // skip version byte

    memmove(&chainId, ptr, sizeof(chainId));
    ptr += sizeof(chainId);

    if (!isValidChainId(chainId)) {
        return R_BAD_CHAIN_ID_ERR;
    }

    memmove(&exchangeChainId, ptr, sizeof(exchangeChainId));
    ptr += sizeof(exchangeChainId);

    if (!isValidChainId(exchangeChainId)) {
        return R_BAD_CHAIN_ID_ERR;
    }

    memmove(&quantityQNT, ptr, sizeof(quantityQNT));
    ptr += sizeof(quantityQNT);

    memmove(&priceNQT, ptr, sizeof(priceNQT));

    state.txnAuth.attachment.coinExchange.chainId = chainId;
    state.txnAuth.attachment.coinExchange.exchangeChainId = exchangeChainId;
    state.txnAuth.attachment.coinExchange.quantityQNT = quantityQNT;
    state.txnAuth.attachment.coinExchange.priceNQT = priceNQT;
    return R_SUCCESS;
}

// PARSE_FN_ASSET_ORDER_PLACEMENT_ATTACHMENT 5
// Parses a specific type of attachment
static uint8_t parseAssetOrderPlacementAttachment() {
    uint64_t assetId = 0;      // assetId
    uint64_t quantityQNT = 0;  // quantityQNT
    uint64_t priceNQT = 0;     // priceNQT

    uint8_t* ptr =
        readFromBuffer(sizeof(uint8_t) + sizeof(state.txnAuth.attachment.assetOrderPlacement));
    if (ptr == 0) {
        return R_SEND_MORE_BYTES;
    }

    ptr += 1;  // skip version byte

    memmove(&assetId, ptr, sizeof(assetId));
    ptr += sizeof(assetId);

    memmove(&quantityQNT, ptr, sizeof(quantityQNT));
    ptr += sizeof(quantityQNT);

    memmove(&priceNQT, ptr, sizeof(priceNQT));

    state.txnAuth.attachment.assetOrderPlacement.assetId = assetId;
    state.txnAuth.attachment.assetOrderPlacement.quantityQNT = quantityQNT;
    state.txnAuth.attachment.assetOrderPlacement.priceNQT = priceNQT;
    return R_SUCCESS;
}

// PARSE_FN_IGNORE_BYTES_UNTIL_THE_END 6
// Parses all the bytes until the endof the txn, since we don't parse the specifics of all the
// types, sometimes this is needed
static uint8_t parseIgnoreBytesUntilTheEnd() {
    while (state.txnAuth.numBytesRead != state.txnAuth.txnSizeBytes) {
        uint8_t* ptr = readFromBuffer(1);
        if (ptr == 0) {
            return R_SEND_MORE_BYTES;
        }
        if (*ptr != 0) {
            state.txnAuth.requiresBlindSigning = true;
        }
    }

    return R_SUCCESS;
}

// PARSE_FN_ASSET_TRANSFER_ATTACHMENT 7
static uint8_t parseAssetTransferAttachment() {
    uint64_t assetId;      // asset id
    uint64_t quantityQNT;  // quantity

    uint8_t* ptr = readFromBuffer(sizeof(uint8_t) + sizeof(state.txnAuth.attachment.assetTransfer));
    if (ptr == 0) {
        return R_SEND_MORE_BYTES;
    }

    if (*ptr != 1) {
        return R_UNSUPPORTED_ATTACHMENT_VERSION;
    }

    ptr += 1;  // skip version byte

    memmove(&assetId, ptr, sizeof(assetId));
    ptr += sizeof(assetId);

    memmove(&quantityQNT, ptr, sizeof(quantityQNT));

    state.txnAuth.attachment.assetTransfer.assetId = assetId;
    state.txnAuth.attachment.assetTransfer.quantityQNT = quantityQNT;
    return R_SUCCESS;
}

// Addes bytes to the read buffer
//@param newData: ptr to the data
//@param numBytes: number of bytes in the data
// return the return value from returnValues.h (R_SUCCESS on success)
uint8_t addToReadBuffer(const uint8_t* const newData, const uint8_t numBytes) {
    uint16_t offset = state.txnAuth.readBufferReadOffset;
    for (uint16_t i = 0; i < state.txnAuth.readBufferEndPos - offset; i++) {
        state.txnAuth.readBuffer[i] = state.txnAuth.readBuffer[i + offset];
    }

    explicit_bzero(state.txnAuth.readBuffer + state.txnAuth.readBufferEndPos - offset, offset);

    state.txnAuth.readBufferEndPos -= offset;
    state.txnAuth.readBufferReadOffset = 0;

    if (state.txnAuth.readBufferEndPos + numBytes > sizeof(state.txnAuth.readBuffer)) {
        return R_NO_SPACE_BUFFER_TOO_SMALL;
    }

    cx_err_t ret = cx_hash_no_throw(&state.txnAuth.hashstate.header, 0, newData, numBytes, 0, 0);
    if (ret != CX_OK) {
        return R_CXLIB_ERROR;
    }

    memcpy(state.txnAuth.readBuffer + state.txnAuth.readBufferEndPos, newData, numBytes);
    state.txnAuth.readBufferEndPos += numBytes;

    return R_SUCCESS;
}

// Since we can't store function pointers in the functionstack, we store number and then call the
// following function to make a call to the corresponding function
static uint8_t callFunctionNumber(const uint8_t functionNum) {
    switch (functionNum) {
        case PARSE_FN_MAIN:
            return parseMainTxnData();
        case PARSE_FN_APPENDAGES_FLAGS:
            return parseAppendagesFlags();
        case PARSE_FN_FXT_COIN_EXCHANGE_ORDER_ISSUE_OR_COIN_EXCHANGE_ORDER_ISSUE_ATTACHMENT:
            return parseFxtCoinExchangeOrderIssueOrCoinExchangeOrderIssueAttachment();
        case PARSE_FN_ASSET_ORDER_PLACEMENT_ATTACHMENT:
            return parseAssetOrderPlacementAttachment();
        case PARSE_FN_IGNORE_BYTES_UNTIL_THE_END:
            return parseIgnoreBytesUntilTheEnd();
        case PARSE_FN_ASSET_TRANSFER_ATTACHMENT:
            return parseAssetTransferAttachment();
    }

    return R_PARSE_FUNCTION_NOT_FOUND;
}

// This function manages the parsing of the readBuffer with functionStack functions
// If there aren't enough bytes in the read buffer it returns R_SEND_MORE_BYTES
// which will be sent back to the user
uint8_t parseTransaction(uint8_t (*setScreenTexts)()) {
    uint8_t ret = R_SUCCESS;
    while (ret == R_SUCCESS) {
        if (state.txnAuth.numFunctionsOnStack == 0) {
            if (state.txnAuth.readBufferEndPos != state.txnAuth.readBufferReadOffset) {
                return R_NOT_ALL_BYTES_READ;
            }

            ret = (*setScreenTexts)();

            if (ret != R_SUCCESS) {
                return ret;
            }

            return R_SHOW_DISPLAY;
        }

        ret = callFunctionNumber(state.txnAuth.functionStack[0]);

        if (ret == R_SEND_MORE_BYTES) {
            return ret;
        }

        uint8_t tempBuffer[FUNCTION_STACK_SIZE - 1];
        memmove(tempBuffer, state.txnAuth.functionStack + 1, sizeof(tempBuffer));
        memmove(state.txnAuth.functionStack, tempBuffer, sizeof(tempBuffer));
        state.txnAuth.functionStack[sizeof(state.txnAuth.functionStack) - 1] = 0;
        state.txnAuth.numFunctionsOnStack--;
    }
    return ret;
}
