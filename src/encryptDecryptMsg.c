/*******************************************************************************
*  (c) 2019 Haim Bender
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

#include <os.h>
#include <os_io_seproxyhal.h>
#include "ux.h"

#include "aes/aes.h"

#include "ardor.h"
#include "returnValues.h"

#define P1_INIT_ENCRYPT                     1
#define P1_INIT_DECRYPT_HIDE_SHARED_KEY     2
#define P1_INIT_DECRYPT_SHOW_SHARED_KEY     3
#define P1_AES_ENCRYPT_DECRYPT              4

#define STATE_INVAILD       0
#define STATE_BUTTON        1
#define STATE_AUTHORIZED    2

/*

    This command allows the client to encrypt and decrypt messages that are assigned to some foreign public key and nonce
    First you need to call the right INIT function, you have 3 choices. After that you call P1_AES_ENCRYPT_DECRYPT as many times as you need

    //todo describe the msg size and in other places the endian'nes of the code

    API:

        P1: P1_INIT_ENCRYPT:
        dataBuffer: msg size (uint16) | derivation path (uint32) * some length | second party public key
        returns:    1 byte status | nonce (on success) | IV

        P1: P1_INIT_DECRYPT_HIDE_SHARED_KEY:
        dataBuffer: msg size (uint16) | derivaiton path (uint32) * some length | second party public key | nonce | IV
        returns:    1 byte status

        P1: P1_INIT_DECRYPT_SHOW_SHARED_KEY:
        dataBuffer: msg size (uint16) | derivaiton path (uint32) * some length | second party public key | nonce | IV
        returns:    1 byte status | sharedkey 32 bytes

        P1_AES_ENCRYPT_DECRYPT:
        dataBuffer: buffer (224 max size) should be in modulu of 16 
        returns:    encrypted / decrypted buffer (same size as input)


    msg size should be of modulu 16 also and bigger then 0
*/


void cleanEncryptionState() {
    state.encryption.state = STATE_INVAILD;
    state.encryption.mode = 0;
    state.encryption.messageLengthBytes = 0;

    os_memset(state.encryption.cbc, 0, sizeof(state.encryption.cbc));
    os_memset(state.encryption.ctx, 0, sizeof(state.encryption.ctx));
    os_memset(state.encryption.nonce, 0, sizeof(state.encryption.nonce));
    os_memset(state.encryption.sharedKey, 0, sizeof(state.encryption.sharedKey));
}

static const bagl_element_t ui_screen[] = {
        UI_BACKGROUND(),
        {{BAGL_ICON,0x00,3,12,7,7,0,0,0,0xFFFFFF,0,0,BAGL_GLYPH_ICON_CROSS},NULL,0,0,0,NULL,NULL,NULL},
        {{BAGL_ICON,0x00,117,13,8,6,0,0,0,0xFFFFFF,0,0,BAGL_GLYPH_ICON_CHECK},NULL,0,0,0,NULL,NULL,NULL},        
        UI_TEXT(0x00, 0, 12, 128, state.encryption.dialogTitle),
        {{BAGL_LABELINE,0x01,15,26,98,12,10,0,0,0xFFFFFF,0,BAGL_FONT_OPEN_SANS_EXTRABOLD_11px|BAGL_FONT_ALIGNMENT_CENTER,26},(char*)state.encryption.dialogContent,0,0,0,NULL,NULL,NULL}
};

static unsigned int ui_screen_button(const unsigned int button_mask, const unsigned int button_mask_counter) {

    uint tx = 0;

    PRINTF("ASDASD");

    switch (button_mask) {
        case BUTTON_EVT_RELEASED | BUTTON_RIGHT:

            PRINTF("ASDASD1");

            G_io_apdu_buffer[tx++] = R_SUCCESS;

            if (P1_INIT_ENCRYPT == state.encryption.mode) {
                os_memcpy(G_io_apdu_buffer + tx, state.encryption.nonce, sizeof(state.encryption.nonce));
                tx += 32;
                os_memcpy(G_io_apdu_buffer + tx, state.encryption.cbc, sizeof(state.encryption.cbc)); //The IV
                tx += sizeof(state.encryption.cbc);
            } else if (P1_INIT_DECRYPT_SHOW_SHARED_KEY == state.encryption.mode) {
                os_memcpy(G_io_apdu_buffer + tx, state.encryption.sharedKey, sizeof(state.encryption.sharedKey));
                tx += 32;
            }

            PRINTF("ASDASD2");

            os_memset(state.encryption.sharedKey, 0, sizeof(state.encryption.sharedKey)); //cleaning as soon as possible, the actuable key we are using to do the work is in ctx
            state.encryption.state = STATE_AUTHORIZED;

            break;

        case BUTTON_EVT_RELEASED | BUTTON_LEFT:

            cleanEncryptionState();
            G_io_apdu_buffer[tx++] = R_REJECT;

            break;

        default:

            return 0;
    }

    PRINTF("ASDASD3");

    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    ui_idle();

    return 0;
}

void encryptDecryptMessageHandlerHelper(const uint8_t p1, const uint8_t p2, const uint8_t * const dataBuffer, const uint8_t dataLength,
                volatile unsigned int * const flags, volatile unsigned int * const tx, const bool isLastCommandDifferent) {

    if ((P1_INIT_ENCRYPT == p1) || (P1_INIT_DECRYPT_HIDE_SHARED_KEY == p1) || (P1_INIT_DECRYPT_SHOW_SHARED_KEY == p1)) {

        cleanEncryptionState();

        if (0 != (dataLength - sizeof(state.encryption.messageLengthBytes)) % sizeof(uint32_t)) {
            G_io_apdu_buffer[(*tx)++] = R_WRONG_SIZE_ERR;
            return;
        }

        uint8_t derivationLength = 0;

        if (P1_INIT_ENCRYPT == p1)
            derivationLength = (dataLength - 32 - sizeof(state.encryption.messageLengthBytes)) / sizeof(uint32_t);
        else
            derivationLength = (dataLength - 32 * 2 - 16 - sizeof(state.encryption.messageLengthBytes)) / sizeof(uint32_t);

        //todo swap these out for consts
        if (2 > derivationLength) {
            G_io_apdu_buffer[(*tx)++] = R_DERIVATION_PATH_TOO_SHORT;
            return;
        }

        if (32 < derivationLength) {
            G_io_apdu_buffer[(*tx)++] = R_DERIVATION_PATH_TOO_LONG;
            return;
        }

        os_memcpy(&state.encryption.messageLengthBytes, dataBuffer, sizeof(state.encryption.messageLengthBytes));

        if ((0 == state.encryption.messageLengthBytes) || (0 != state.encryption.messageLengthBytes % 16)) {
            cleanEncryptionState();
            G_io_apdu_buffer[(*tx)++] = R_BAD_MSG_LENGTH;
            return;
        }

        uint32_t derivationPath[32]; //todo check if i can just point to the derivation path
        os_memcpy(derivationPath, dataBuffer + sizeof(state.encryption.messageLengthBytes), derivationLength * sizeof(uint32_t));

        PRINTF("\n checkK6 %d %d\n", check_canary(), derivationPath);
        PRINTF("\n checkK6 %d %d\n", check_canary(), derivationPath);

        uint8_t exceptionOut = 0;
        uint64_t localAddressId;

        uint8_t * noncePtr = dataBuffer + derivationLength * sizeof(uint32_t) + 32 + sizeof(state.encryption.messageLengthBytes);

        PRINTF("\n checkK5 %d %d\n", check_canary(), noncePtr);

        if (P1_INIT_ENCRYPT == p1) {
            cx_rng(state.encryption.nonce, sizeof(state.encryption.nonce));
            noncePtr = state.encryption.nonce; //if we are decrypting then we are using from the command
        }

        uint8_t ret = getSharedEncryptionKey(derivationPath, derivationLength, dataBuffer + derivationLength * sizeof(uint32_t) + sizeof(state.encryption.messageLengthBytes), 
            noncePtr, &exceptionOut, state.encryption.sharedKey, &localAddressId);


        snprintf(state.encryption.dialogContent, sizeof(state.encryption.dialogContent), "%d bytes between your %s-", state.encryption.messageLengthBytes, APP_PREFIX);
        uint8_t tempLength = strlen(state.encryption.dialogContent);
        reedSolomonEncode(localAddressId, state.encryption.dialogContent + tempLength);
        tempLength += 20; //todo move to const
        
        PRINTF("\n checkK4 %d\n", check_canary());

        snprintf(state.encryption.dialogContent + tempLength, sizeof(state.encryption.dialogContent) - tempLength, " and %s-", APP_PREFIX);
        tempLength += 6 + strlen(APP_PREFIX);
        reedSolomonEncode(publicKeyToId(dataBuffer + derivationLength * sizeof(uint32_t) + sizeof(state.encryption.messageLengthBytes)), state.encryption.dialogContent + tempLength);
        tempLength += 20;

        PRINTF("\n checkK3 %d\n", check_canary());

        if (P1_INIT_DECRYPT_SHOW_SHARED_KEY == p1)
            snprintf(state.encryption.dialogContent + tempLength, sizeof(state.encryption.dialogContent) - tempLength, " and share encryption key");

        PRINTF("ddd %d %d", strlen(state.encryption.dialogContent), strlen(APP_PREFIX));

        if (R_KEY_DERIVATION_EX == ret) {
            cleanEncryptionState();
            G_io_apdu_buffer[(*tx)++] = ret;
            G_io_apdu_buffer[(*tx)++] = exceptionOut >> 8;
            G_io_apdu_buffer[(*tx)++] = exceptionOut & 0xFF;
            return;
        } else if (R_SUCCESS != ret) {
            cleanEncryptionState();
            G_io_apdu_buffer[(*tx)++] = ret;
            return;
        }

        PRINTF("\n checkK2 %d\n", check_canary());

        if (P1_INIT_ENCRYPT == p1) {
            snprintf(state.encryption.dialogTitle, sizeof(state.encryption.dialogTitle), "Msg Encryption");

            if (!aes_encrypt_init_fixed(state.encryption.sharedKey, sizeof(state.encryption.sharedKey), state.encryption.ctx)) {
                cleanEncryptionState();
                G_io_apdu_buffer[(*tx)++] = R_AES_ERROR;
                return;
            }

            os_memset(state.encryption.sharedKey, 0, sizeof(state.encryption.sharedKey)); //cleaning as soon as possible, the actuable key we are using to do the work is in ctx
            cx_rng(state.encryption.cbc, sizeof(state.encryption.cbc));

        } else {
            snprintf(state.encryption.dialogTitle, sizeof(state.encryption.dialogTitle), "Msg Decryption");

            if (!aes_decrypt_init_fixed(state.encryption.sharedKey, sizeof(state.encryption.sharedKey), state.encryption.ctx)) {
                cleanEncryptionState();
                G_io_apdu_buffer[(*tx)++] = R_AES_ERROR;
                return;
            }

            if (P1_INIT_DECRYPT_HIDE_SHARED_KEY == p1) {
                os_memset(state.encryption.sharedKey, 0, sizeof(state.encryption.sharedKey)); //cleaning as soon as possible, the actuable key we are using to do the work is in ctx
            }

            os_memcpy(state.encryption.cbc, dataBuffer + dataLength - sizeof(state.encryption.cbc), sizeof(state.encryption.cbc)); //Copying the IV into the CBC
        }

        state.encryption.state = STATE_BUTTON;
        state.encryption.mode = p1;

        PRINTF("\n checkK1 %d\n", check_canary());

        UX_DISPLAY(ui_screen, (bagl_element_callback_t)makeTextGoAround_preprocessor)
        *flags |= IO_ASYNCH_REPLY;

    } else if (P1_AES_ENCRYPT_DECRYPT == p1) {

        if (isLastCommandDifferent) {
            cleanEncryptionState();
            G_io_apdu_buffer[(*tx)++] = R_NO_SETUP;
            return;
        }

        if (STATE_AUTHORIZED != state.encryption.state) {
            cleanEncryptionState();
            G_io_apdu_buffer[(*tx)++] = R_NO_SETUP_OR_AUTHORIZATION;
            return;
        }

        if (0 != dataLength % 16) {
            cleanEncryptionState();
            G_io_apdu_buffer[(*tx)++] = R_WRONG_SIZE_MODULO_ERR;
            return;
        }

        if (state.encryption.messageLengthBytes < dataLength) {
            cleanEncryptionState();
            G_io_apdu_buffer[(*tx)++] = R_BAD_MSG_LENGTH;
            return;
        }

        state.encryption.messageLengthBytes -= dataLength;

        uint8_t * pos = dataBuffer;
        uint8_t tmp[AES_BLOCK_SIZE];

        while (pos < dataBuffer + dataLength) {
            if (P1_INIT_ENCRYPT == state.encryption.mode) { //if we are doing encryption:

                for (uint8_t j = 0; j < AES_BLOCK_SIZE; j++)
                    state.encryption.cbc[j] ^= pos[j];

                aes_encrypt(state.encryption.ctx, state.encryption.cbc, state.encryption.cbc);
                os_memcpy(pos, state.encryption.cbc, AES_BLOCK_SIZE);
            } else {
                os_memcpy(tmp, pos, AES_BLOCK_SIZE);
                aes_decrypt(state.encryption.ctx, pos, pos);
                for (uint8_t j = 0; j < AES_BLOCK_SIZE; j++)
                    pos[j] ^= state.encryption.cbc[j];

                os_memcpy(state.encryption.cbc, tmp, AES_BLOCK_SIZE);
            }

            pos += AES_BLOCK_SIZE;
        }

        *tx = 1 + dataLength;

        for (uint8_t i = 0; i < dataLength; i++)
                G_io_apdu_buffer[i+1] = dataBuffer[i];

        G_io_apdu_buffer[0] = R_SUCCESS;

    } else {
        cleanEncryptionState();
        G_io_apdu_buffer[(*tx)++] = R_UNKOWN_CMD;
    }
}

void encryptDecryptMessageHandler(const uint8_t p1, const uint8_t p2, const uint8_t * const dataBuffer, const uint8_t dataLength,
                volatile unsigned int * const flags, volatile unsigned int * const tx, const bool isLastCommandDifferent) {

    encryptDecryptMessageHandlerHelper(p1, p2, dataBuffer, dataLength, flags, tx, isLastCommandDifferent);
    
    if (0 == ((*flags) & IO_ASYNCH_REPLY)) {
        G_io_apdu_buffer[(*tx)++] = 0x90;
        G_io_apdu_buffer[(*tx)++] = 0x00;
    }
}
