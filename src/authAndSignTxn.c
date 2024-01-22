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
#include <stdbool.h>

#include "io.h"      // io_send*
#include "parser.h"  // command_t

#include "glyphs.h"
#include "returnValues.h"
#include "config.h"
#include "ardor.h"
#include "reedSolomon.h"
#include "transactionParser.h"
#include "ui/menu.h"
#include "ui/display.h"
#include "io_helper.h"  // io_send_return*

#define P1_INIT 1
#define P1_CONTINUE 2
#define P1_SIGN 3

#define MODE_P1_MASK 0b00000011
#define TX_SIZE_P1_MASK 0b11111100
#define TX_SIZE_P1_SHIFT 6

// This is the code that parses the txn for signing, it parses streamed tx bytes into the state
// object while hashing the bytes to be signed later, displays a dialog of screens which contain the
// parsed txn bytes from the state. It solves 2 no trivial problems:
// 1 - Allowing txn bytes to be parsed from a stream of bytes (this is very hard, since we don't
//     have a lot memory, so we need to parse bytes and forget about them)
// 2 - txn's very in length depending on type, so the same bytes are sometimes not parsed into the
//     same place, so it has to be dynamic about parsing
//
//
// The way these problems are solved is by the following flow:
//
// The function stack is initiated with an index reference to parseMainTxnData
//
//
// authAndSignTxnHandlerHelper is called with some of the txn bytes
// => addToReadBuffer is called adds these bytes to the read buffer
// => parseTransaction is called,
//    which calls the first parse function on the stack which is parseMainTxnData
// => parseMainTxnData trys to pull 142 bytes from the buffer
//      if there is are 142 bytes there:
//          parseMainTxnData parses the main txn bytes and then adds more functions to parse stack
//          depending on the appendages
//      else
//          R_SEND_MORE_BYTES is trickled down by the function to be sent to back to the client
//
// And so on the process goes until the stack of functions is empty and there are no more bytes in
// the read buffer. If the parsing goes well without errors => setScreenTexts(); is called which
// sets up the labels and first screen of the authorization dialog.

//  API:
//
//
//      The mode is encoded in the first 2 bits of the p1 parameter and the size of the txn should
//      be ((p1 & 0b11111100) << 6) + p2 you only need to pass the size when calling P1_INIT
//
//      P1: P1_INIT:
//      dataBuffer: txn bytes //you can send all of your bytes here if you want
//      returns:    1 byte status
//
//      P1: P1_CONTINUE:    more txn bytes
//      returns:    1 byte status
//
//      P1: P1_SIGN:
//      dataBuffer: derivaiton path (uint32) * some length
//      returns:    1 bytes status | 64 byte signiture

static void initTxnAuthState() {
    cleanState();

    state.txnAuth.functionStack[0] = PARSE_FN_MAIN;  // Add the first parse function on the stack
    state.txnAuth.functionStack[1] = PARSE_FN_APPENDAGES_FLAGS;  // The appendages parse function
    state.txnAuth.numFunctionsOnStack = 2;

    cx_sha256_init(&state.txnAuth.hashstate);
}

static int cleanAndReturn(uint8_t ret) {
    cleanState();
    return io_send_return1(ret);
}

// Accept click callback
void signTransactionConfirm() {
    state.txnAuth.state = AUTH_STATE_USER_AUTHORIZED;
    io_send_return2(R_SUCCESS, R_FINISHED);
}

// Canceled click callback
void signTransactionCancel() {
    cleanState();
    io_send_return2(R_SUCCESS, R_REJECT);
}

/**
 * Sets the title and text for one of the optional windows in the transaction authorization screen.
 * The title is a regular text, the text is formatted as an integer.
 *
 * @param windowIndex The index of the window to print the amount for.
 * @param title The title to display for the window.
 * @param amount The amount to display in the window text.
 */
static void printWindowAmount(uint8_t windowIndex, const char* title, uint64_t amount) {
    snprintf(state.txnAuth.windowTitles[windowIndex],
             sizeof(state.txnAuth.windowTitles[windowIndex]),
             "%s",
             title);
    formatAmount(state.txnAuth.windowTexts[windowIndex],
                 sizeof(state.txnAuth.windowTexts[windowIndex]),
                 amount,
                 0);
}

static uint8_t setPaymentsScreenTexts() {
    snprintf(state.txnAuth.windowTitles[0], sizeof(state.txnAuth.windowTitles[0]), "Amount");

    uint8_t ret = formatChainAmount(state.txnAuth.windowTexts[0],
                                    sizeof(state.txnAuth.windowTexts[0]),
                                    state.txnAuth.amount,
                                    state.txnAuth.chainId);
    if (ret == 0) {
        return R_FORMAT_AMOUNT_ERR;
    }

    snprintf(state.txnAuth.windowTitles[1], sizeof(state.txnAuth.windowTitles[1]), "Recipient");
    snprintf(state.txnAuth.windowTexts[1], sizeof(state.txnAuth.windowTexts[1]), APP_PREFIX);
    reedSolomonEncode(state.txnAuth.recipientId,
                      state.txnAuth.windowTexts[1] + strlen(state.txnAuth.windowTexts[1]));

    return R_SUCCESS;
}

static uint8_t setCoinExchangeScreenTexts() {
    snprintf(state.txnAuth.windowTitles[0], sizeof(state.txnAuth.windowTitles[0]), "Amount");

    uint8_t ret = formatAmount(
        state.txnAuth.windowTexts[0],
        sizeof(state.txnAuth.windowTexts[0]),
        state.txnAuth.attachment.coinExchange.quantityQNT,
        chainNumDecimalsBeforePoint(state.txnAuth.attachment.coinExchange.exchangeChainId));

    if (ret == 0) {
        return R_FORMAT_AMOUNT_ERR;
    }

    // the existence of the chainId and exchangeId chains was already checked in transactionParser.c

    snprintf(state.txnAuth.windowTexts[0] + ret - 1,
             sizeof(state.txnAuth.windowTexts[0]) - ret - 1,
             " %s",
             chainName(state.txnAuth.attachment.coinExchange.exchangeChainId));

    snprintf(state.txnAuth.windowTitles[1],
             sizeof(state.txnAuth.windowTitles[1]),
             "Price per %s",
             chainName(state.txnAuth.attachment.coinExchange.exchangeChainId));
    ret = formatAmount(state.txnAuth.windowTexts[1],
                       sizeof(state.txnAuth.windowTexts[1]),
                       state.txnAuth.attachment.coinExchange.priceNQT,
                       chainNumDecimalsBeforePoint(state.txnAuth.attachment.coinExchange.chainId));

    if (ret == 0) {
        return R_FORMAT_AMOUNT_ERR;
    }

    snprintf(state.txnAuth.windowTexts[1] + ret - 1,
             sizeof(state.txnAuth.windowTexts[1]) - ret - 1,
             " %s",
             chainName(state.txnAuth.attachment.coinExchange.chainId));

    return R_SUCCESS;
}

static uint8_t setAssetOrderScreenTexts() {
    printWindowAmount(0, "Asset Id", state.txnAuth.attachment.assetOrderPlacement.assetId);
    printWindowAmount(1, "Quantity QNT", state.txnAuth.attachment.assetOrderPlacement.quantityQNT);
    printWindowAmount(2, "Price NQT", state.txnAuth.attachment.assetOrderPlacement.priceNQT);
    return R_SUCCESS;
}

static uint8_t setAssetTransferScreenTexts() {
    printWindowAmount(0, "Asset Id", state.txnAuth.attachment.assetTransfer.assetId);
    printWindowAmount(1, "Quantity QNT", state.txnAuth.attachment.assetTransfer.quantityQNT);

    snprintf(state.txnAuth.windowTitles[2], sizeof(state.txnAuth.windowTitles[2]), "Recipient");
    snprintf(state.txnAuth.windowTexts[2], sizeof(state.txnAuth.windowTexts[2]), APP_PREFIX);
    reedSolomonEncode(state.txnAuth.recipientId,
                      state.txnAuth.windowTexts[2] + strlen(state.txnAuth.windowTexts[2]));

    return R_SUCCESS;
}

// This function formats trxn data into text memebers of the state which the UI flow will read from
// Returns: Success iff everything is good, otherwise probably some kind of formating error
uint8_t setScreenTexts() {
    if (state.txnAuth.txnTypeIndex < LEN_TXN_TYPES) {
        switch (state.txnAuth.txnTypeAndSubType) {
            case TX_TYPE_ORDINARY_PAYMENT:
            case TX_TYPE_FXT_PAYMENT:
                return setPaymentsScreenTexts();

            case TX_TYPE_FXT_COIN_EXCHANGE_ORDER_ISSUE:
            case TX_TYPE_COIN_EXCHANGE_ORDER_ISSUE:
                return setCoinExchangeScreenTexts();

            case TX_TYPE_ASK_ORDER_PLACEMENT:
            case TX_TYPE_BID_ORDER_PLACEMENT:
                return setAssetOrderScreenTexts();

            case TX_TYPE_ASSET_TRANSFER:
                return setAssetTransferScreenTexts();
        }
    }

    return R_SUCCESS;
}

// This is the function used to sign the hash of the txn
//@param txnSha256 -                     ptr to 32 byte sha256 of the txn
//@param derivationPath -                ptr to the derivation path buffer
//@param derivationPathLengthInUints32 - length of the derivation path buffer
//@param destBuffer -                    ptr to 64 bytes of memory of where to write the buffer
//@param outException out -              ptr to where to write the exception if it happends
//@returns R_SUCCESS iff success else the appropriate error code is returned

uint8_t signTxn(const uint8_t* const derivationPath,
                const uint8_t derivationPathLengthInUints32,
                uint8_t* const destBuffer,
                uint16_t* const outException) {
    uint8_t keySeed[32];
    explicit_bzero(keySeed, sizeof(keySeed));
    uint8_t ret = 0;

    ret = ardorKeys(derivationPath, derivationPathLengthInUints32, keySeed, 0, 0, 0, outException);
    if (ret != R_SUCCESS) {
        explicit_bzero(keySeed, sizeof(keySeed));
        return ret;
    }

    uint8_t txHash[32];
    cx_err_t err =
        cx_hash_no_throw(&state.txnAuth.hashstate.header, CX_LAST, 0, 0, txHash, sizeof(txHash));
    if (err != CX_OK) {
        return R_CXLIB_ERROR;
    }

    // sign msg should only use the first 32 bytes of keyseed
    err = signMsg(keySeed, txHash, destBuffer);
    if (err != CX_OK) {
        return R_CXLIB_ERROR;
    }

    // clean buffers
    explicit_bzero(txHash, sizeof(txHash));
    explicit_bzero(keySeed, sizeof(keySeed));

    return R_SUCCESS;
}

//// HANDLER MAIN FUNCTIONS

static int p1InitContinueCommon(const command_t* const cmd) {
    state.txnAuth.state = AUTH_STATE_PARSING;

    uint8_t ret = addToReadBuffer(cmd->data, cmd->lc);

    if (ret != R_SUCCESS) {
        return cleanAndReturn(ret);
    }

    ret = parseTransaction(&setScreenTexts);

    if (ret == R_SHOW_DISPLAY) {
        signTransactionScreen();
        return 0;
    }

    if ((ret != R_SEND_MORE_BYTES) && (ret != R_FINISHED)) {
        cleanState();
    }

    return io_send_return2(R_SUCCESS, ret);
}

static int p1InitHandler(const command_t* const cmd) {
    initTxnAuthState();

    state.txnAuth.txnSizeBytes = ((cmd->p1 & TX_SIZE_P1_MASK) << TX_SIZE_P1_SHIFT) + cmd->p2;

    if (state.txnAuth.txnSizeBytes < BASE_TRANSACTION_SIZE) {
        return io_send_response_pointer(&(const uint8_t){R_TXN_SIZE_TOO_SMALL}, 1, SW_OK);
    }

    return p1InitContinueCommon(cmd);
}

static int p1ContinueHandler(const command_t* const cmd) {
    if (state.txnAuth.state == AUTH_STATE_USER_AUTHORIZED) {
        return cleanAndReturn(R_NOT_ALL_BYTES_USED);
    }

    if (state.txnAuth.state == AUTH_STATE_INIT) {
        return cleanAndReturn(R_ERR_NO_INIT_CANT_CONTINUE);
    }

    return p1InitContinueCommon(cmd);
}

static int p1SignHandler(const command_t* const cmd) {
    if (state.txnAuth.state != AUTH_STATE_USER_AUTHORIZED) {
        return cleanAndReturn(R_TXN_UNAUTHORIZED);
    }

    // dataLength is the derivation path length in bytes
    if (!isValidDerivationPathLength(cmd->lc)) {
        return cleanAndReturn(R_WRONG_SIZE_ERR);
    }

    uint16_t exception = 0;
    uint8_t buffer[1 + SIGNATURE_SIZE];
    buffer[0] = R_SUCCESS;
    uint8_t ret = signTxn(cmd->data, cmd->lc / 4, buffer + 1, &exception);

    cleanState();

    if (ret == R_SUCCESS) {
        return io_send_response_pointer(buffer, sizeof(buffer), SW_OK);
    } else if (ret == R_KEY_DERIVATION_EX) {
        return io_send_return3(ret, exception >> 8, exception & 0xFF);
    } else {
        return io_send_return1(ret);
    }
}

// This is the main command handler, it checks that params are in the right size,
// and manages calls to initTxnAuthState(), signTxn(), addToReadBuffer(), parseTransaction()
// Since this is a callback function, and this handler manages state, it's this function's
// reposibility to call initTxnAuthState Every time we get some sort of an error
int authAndSignTxnHandler(const command_t* const cmd) {
    if (cmd->lc < 1) {
        return cleanAndReturn(R_WRONG_SIZE_ERR);
    } else if ((cmd->p1 & MODE_P1_MASK) == P1_INIT) {
        return p1InitHandler(cmd);
    } else if ((cmd->p1 & MODE_P1_MASK) == P1_CONTINUE) {
        return p1ContinueHandler(cmd);
    } else if ((cmd->p1 & MODE_P1_MASK) == P1_SIGN) {
        return p1SignHandler(cmd);
    } else {
        return io_send_return1(R_UNKNOWN_CMD_PARAM_ERR);
    }
}
