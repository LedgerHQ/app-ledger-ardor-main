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

#include <os.h>
#include "io.h"      // io_send*
#include "parser.h"  // command_t

#include "returnValues.h"
#include "config.h"
#include "ardor.h"
#include "io_helper.h"

#define P1_INIT_ENCRYPT 1
#define P1_INIT_DECRYPT_HIDE_SHARED_KEY 2
#define P1_INIT_DECRYPT_SHOW_SHARED_KEY 3
#define P1_AES_ENCRYPT_DECRYPT 4

#define NONCE_LENGTH 32
#define IV_LENGTH 16

/*

   This command allows the client to encrypt and decrypt messages that are assigned to some foreign
   public key. First you need to call the right INIT function, you have 3 choices. After
   that you call P1_AES_ENCRYPT_DECRYPT as many times as you need

    API:

        P1: P1_INIT_ENCRYPT:
        dataBuffer: derivation path (uint32) * some length | second party public key
        returns:    1 byte status | nonce (on success) | IV

        P1: P1_INIT_DECRYPT_HIDE_SHARED_KEY:
        dataBuffer: derivation path (uint32) * some length | second party public key | nonce | IV
        returns:    1 byte status

        P1: P1_INIT_DECRYPT_SHOW_SHARED_KEY:
        dataBuffer: derivation path (uint32) * some length | second party public key | nonce | IV
        returns:    1 byte status | sharedkey 32 bytes

        P1_AES_ENCRYPT_DECRYPT:
        dataBuffer: buffer (224 max size) should be in modulo 16
        returns:    1 bytes status | encrypted / decrypted buffer (same size as input)
*/

static int cleanAndReturn(uint8_t ret) {
    cleanState();
    return io_send_return1(ret);
}

static bool getDerivationLength(const uint8_t p1,
                                const uint8_t dataLength,
                                uint8_t* derivationLength) {
    int16_t derivationLengthSigned = 0;

    if (p1 == P1_INIT_ENCRYPT) {
        // no underflow because the type is signed
        derivationLengthSigned = (dataLength - PUBLIC_KEY_SIZE) / sizeof(uint32_t);
    } else {
        derivationLengthSigned =
            (dataLength - PUBLIC_KEY_SIZE - NONCE_LENGTH - IV_LENGTH) / sizeof(uint32_t);
    }

    if ((derivationLengthSigned < MIN_DERIVATION_LENGTH) ||
        (derivationLengthSigned > MAX_DERIVATION_LENGTH)) {
        return false;
    }

    *derivationLength = (uint8_t) derivationLengthSigned;  // cast is ok, because of the check above
    return true;
}

static int initHandler(const command_t* const cmd) {
    if (cmd->lc % sizeof(uint32_t) != 0) {
        return cleanAndReturn(R_WRONG_SIZE_ERR);
    }

    if (cmd->lc > MAX_CHUNK_SIZE_ENCRYPT) {
        return cleanAndReturn(R_NO_SPACE_BUFFER_TOO_SMALL);
    }

    uint8_t derivationLength = 0;
    if (!getDerivationLength(cmd->p1, cmd->lc, &derivationLength)) {
        return cleanAndReturn(R_WRONG_SIZE_ERR);
    }

    uint8_t nonce[NONCE_LENGTH];
    const uint8_t* noncePtr = cmd->data + derivationLength * sizeof(uint32_t) + PUBLIC_KEY_SIZE;

    if (cmd->p1 == P1_INIT_ENCRYPT) {
        cx_trng_get_random_data(nonce, sizeof(nonce));
        noncePtr = nonce;  // if we are decrypting then we are using from the command
    }

    uint16_t exceptionOut = 0;
    uint8_t encryptionKey[32];

    uint8_t ret = getSharedEncryptionKey(cmd->data,
                                         derivationLength,
                                         cmd->data + derivationLength * sizeof(uint32_t),
                                         noncePtr,
                                         &exceptionOut,
                                         encryptionKey);

    if (ret == R_KEY_DERIVATION_EX) {
        cleanState();
        explicit_bzero(encryptionKey, sizeof(encryptionKey));  // cleaning the key from memory
        return io_send_return3(ret, exceptionOut >> 8, exceptionOut & 0xFF);
    } else if (ret != R_SUCCESS) {
        explicit_bzero(encryptionKey, sizeof(encryptionKey));  // cleaning the key from memory
        return cleanAndReturn(ret);
    }

    if (cx_aes_init_key_no_throw(encryptionKey, sizeof(encryptionKey), &state.encryption.aesKey) !=
        CX_OK) {
        return cleanAndReturn(R_AES_ERROR);
    }
    if (cmd->p1 != P1_INIT_ENCRYPT) {
        // Copying the IV into the CBC
        memcpy(state.encryption.cbc,
               cmd->data + cmd->lc - sizeof(state.encryption.cbc),
               sizeof(state.encryption.cbc));
    }

    state.encryption.mode = cmd->p1;
    state.encryption.buffer[0] = R_SUCCESS;
    size_t bufferSize = 1;

    if (cmd->p1 == P1_INIT_ENCRYPT) {
        memcpy(state.encryption.buffer + bufferSize, nonce, sizeof(nonce));
        bufferSize += sizeof(nonce);
        // The IV is stored in the CBC
        cx_trng_get_random_data(state.encryption.cbc, sizeof(state.encryption.cbc));
        memcpy(state.encryption.buffer + bufferSize,
               state.encryption.cbc,
               sizeof(state.encryption.cbc));
        bufferSize += sizeof(state.encryption.cbc);
    } else if (cmd->p1 == P1_INIT_DECRYPT_SHOW_SHARED_KEY) {
        memcpy(state.encryption.buffer + bufferSize, encryptionKey, sizeof(encryptionKey));
        bufferSize += sizeof(encryptionKey);
    }

    explicit_bzero(encryptionKey, sizeof(encryptionKey));  // cleaning the key from memory
    return io_send_response_pointer(state.encryption.buffer, bufferSize, SW_OK);
}

static int aesEncryptDecryptHandler(const command_t* const cmd) {
    if ((state.encryption.mode != P1_INIT_ENCRYPT) &&
        (state.encryption.mode != P1_INIT_DECRYPT_HIDE_SHARED_KEY) &&
        (state.encryption.mode != P1_INIT_DECRYPT_SHOW_SHARED_KEY)) {
        return cleanAndReturn(R_NO_SETUP);
    }

    if (cmd->lc % CX_AES_BLOCK_SIZE != 0) {
        return cleanAndReturn(R_WRONG_SIZE_MODULO_ERR);
    }

    if (cmd->data == 0) {
        return cleanAndReturn(R_NOT_ALL_BYTES_READ);
    }

    uint8_t* inPtr = cmd->data;
    uint8_t* outPtr = state.encryption.buffer + 1;
    state.encryption.buffer[0] = R_SUCCESS;

    uint8_t* cbc = state.encryption.cbc;  // Temporary variable
    while (inPtr < cmd->data + cmd->lc) {
        if (state.encryption.mode == P1_INIT_ENCRYPT) {  // if we are doing encryption
            for (uint8_t j = 0; j < CX_AES_BLOCK_SIZE; j++) {
                cbc[j] ^= inPtr[j];
            }

            if (cx_aes_enc_block(&state.encryption.aesKey, cbc, cbc) != CX_OK) {
                return cleanAndReturn(R_CXLIB_ERROR);
            }
            memcpy(outPtr, cbc, CX_AES_BLOCK_SIZE);
        } else {
            if (cx_aes_dec_block(&state.encryption.aesKey, inPtr, outPtr) != CX_OK) {
                return cleanAndReturn(R_CXLIB_ERROR);
            }

            for (uint8_t j = 0; j < CX_AES_BLOCK_SIZE; j++) {
                outPtr[j] ^= cbc[j];
            }

            memcpy(cbc, inPtr, CX_AES_BLOCK_SIZE);
        }
        inPtr += CX_AES_BLOCK_SIZE;
        outPtr += CX_AES_BLOCK_SIZE;
    }
    return io_send_response_pointer(state.encryption.buffer, cmd->lc + 1, SW_OK);
}

// Since this is a callback function, and the handler manages state, it's this function's
// reposibility to clean the state Every time we get some sort of an error
int encryptDecryptMessageHandler(const command_t* const cmd) {
    if ((cmd->p1 == P1_INIT_ENCRYPT) || (cmd->p1 == P1_INIT_DECRYPT_HIDE_SHARED_KEY) ||
        (cmd->p1 == P1_INIT_DECRYPT_SHOW_SHARED_KEY)) {
        return initHandler(cmd);
    } else if (cmd->p1 == P1_AES_ENCRYPT_DECRYPT) {
        return aesEncryptDecryptHandler(cmd);
    } else {
        return cleanAndReturn(R_UNKOWN_CMD);
    }
}
