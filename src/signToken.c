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

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "io.h"      // io_send*
#include "parser.h"  // command_t

#include "returnValues.h"
#include "config.h"
#include "ardor.h"
#include "ui/menu.h"
#include "ui/display.h"
#include "io_helper.h"

#define P1_INIT 0
#define P1_MSG_BYTES 1
#define P1_SIGN 2

/*
    modes:
        P1_INIT: this commands just clears all bytes in the state
            dataBuffer: empty
            returns:    1 byte status

        P1_MSG_BYTES:
            dataBuffer: message bytes
            returns:    1 byte status

        P1_SIGN:
            dataBuffer: timestamp (4 bytes) | derivation path (uint32) * some length |
            returns:    1 byte status | token 100 bytes

    100-byte token consists of a 32-byte public key, a 4-byte timestamp, and a 64-byte signature
*/

static int cleanAndReturn(uint8_t ret) {
    cleanState();
    return io_send_return1(ret);
}

// UI callback defined in ui/display.h
void signTokenConfirm() {
    uint16_t exception = 0;
    uint8_t keySeed[32];
    explicit_bzero(keySeed, sizeof(keySeed));

    // gotta do some space reuse
    uint8_t publicKeyAndFinalHash[32];
    explicit_bzero(publicKeyAndFinalHash, sizeof(publicKeyAndFinalHash));
    uint8_t ret = ardorKeys(state.tokenSign.ptrDerivationPath,
                            state.tokenSign.derivationPathLengthInUints32,
                            keySeed,
                            publicKeyAndFinalHash,
                            0,
                            0,
                            &exception);

    if (ret != R_SUCCESS) {
        cleanState();
        io_send_return3(ret, exception >> 8, exception & 0xFF);
        return;
    }

    state.tokenSign.token[0] = R_SUCCESS;
    size_t offset = 1;

    cx_err_t err;
    // adding the public key to the hash
    err = cx_hash_no_throw(&state.tokenSign.sha256.header,
                           0,
                           publicKeyAndFinalHash,
                           sizeof(publicKeyAndFinalHash),
                           0,
                           0);
    if (err != CX_OK) {
        cleanAndReturn(R_CXLIB_ERROR);
        return;
    }

    // also make a copy to the output buffer, because of how a token is constructed
    memcpy(state.tokenSign.token + offset, publicKeyAndFinalHash, sizeof(publicKeyAndFinalHash));
    offset += sizeof(publicKeyAndFinalHash);

    // adding the timestamp to the hash
    err = cx_hash_no_throw(&state.tokenSign.sha256.header,
                           0,
                           (uint8_t*) &state.tokenSign.timestamp,
                           sizeof(state.tokenSign.timestamp),
                           0,
                           0);
    if (err != CX_OK) {
        cleanAndReturn(R_CXLIB_ERROR);
        return;
    }

    memcpy(state.tokenSign.token + offset,
           &state.tokenSign.timestamp,
           sizeof(state.tokenSign.timestamp));
    offset += sizeof(state.tokenSign.timestamp);

    err = cx_hash_no_throw(&state.tokenSign.sha256.header,
                           CX_LAST,
                           0,
                           0,
                           publicKeyAndFinalHash,
                           sizeof(publicKeyAndFinalHash));
    if (err != CX_OK) {
        cleanAndReturn(R_CXLIB_ERROR);
        return;
    }

    err = signMsg(keySeed, publicKeyAndFinalHash, state.tokenSign.token + offset);
    if (err != CX_OK) {
        cleanAndReturn(R_CXLIB_ERROR);
        return;
    }
    explicit_bzero(keySeed, sizeof(keySeed));

    io_send_response_pointer(state.tokenSign.token, sizeof(state.tokenSign.token), SW_OK);
    cleanState();
}

// UI callback defined in ui/display.h
void signTokenCancel() {
    cleanState();
    io_send_return2(R_SUCCESS, R_REJECT);
}

static int p1TokenInitHandler() {
    cleanState();
    state.tokenSign.state = SIGN_TOKEN_INIT;
    cx_sha256_init(&state.tokenSign.sha256);
    return io_send_return1(R_SUCCESS);
}

static int p1TokenMsgBytesHandler(const command_t* const cmd) {
    if (state.tokenSign.state == SIGN_TOKEN_UNINIT) {
        return cleanAndReturn(R_WRONG_STATE);
    }

    state.tokenSign.state = SIGN_TOKEN_BYTES_RECEIVED;

    if (cx_hash_no_throw(&state.tokenSign.sha256.header, 0, cmd->data, cmd->lc, 0, 0) != CX_OK) {
        return cleanAndReturn(R_CXLIB_ERROR);
    }

    return io_send_return1(R_SUCCESS);
}

static int p1TokenSignHandler(const command_t* const cmd) {
    if (state.tokenSign.state != SIGN_TOKEN_BYTES_RECEIVED) {
        return cleanAndReturn(R_WRONG_STATE);
    }

    if (cmd->lc < 4) {
        return cleanAndReturn(R_WRONG_SIZE_ERR);
    }

    if ((cmd->lc - 4) % sizeof(uint32_t) != 0) {
        return cleanAndReturn(R_WRONG_SIZE_MODULO_ERR);
    }

    // underflow was checked against above above
    state.tokenSign.derivationPathLengthInUints32 = (cmd->lc - 4) / sizeof(uint32_t);

    if ((state.tokenSign.derivationPathLengthInUints32 < MIN_DERIVATION_LENGTH) ||
        (state.tokenSign.derivationPathLengthInUints32 > MAX_DERIVATION_LENGTH)) {
        return cleanAndReturn(R_WRONG_SIZE_ERR);
    }

    memcpy(&state.tokenSign.timestamp, cmd->data, sizeof(state.tokenSign.timestamp));
    state.tokenSign.ptrDerivationPath = cmd->data + sizeof(state.tokenSign.timestamp);

    signTokenScreen();
    return 0;
}

// Since this is a callback function, and this handler manages state, it's this function's
// reposibility to clear the state Every time we get some sort of an error
int signTokenMessageHandler(const command_t* const cmd) {
    if (cmd->p1 == P1_INIT) {
        return p1TokenInitHandler();
    } else if (cmd->p1 == P1_MSG_BYTES) {
        return p1TokenMsgBytesHandler(cmd);
    } else if (cmd->p1 == P1_SIGN) {
        return p1TokenSignHandler(cmd);
    } else {
        return cleanAndReturn(R_UNKNOWN_CMD_PARAM_ERR);
    }
}
