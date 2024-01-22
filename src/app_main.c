/*******************************************************************************
 *
 *  (c) 2016 Ledger
 *  (c) 2018 Nebulous
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
#include <string.h>

#include "parser.h"  // command_t, apdu_parser
#include "io.h"      // io_init, io_recv_command

#include "config.h"
#include "ardor.h"
#include "returnValues.h"
#include "ui/menu.h"
#include "io_helper.h"

// The APDU protocol uses a single-byte instruction code (INS) to specify
// which command should be executed. We'll use this code to dispatch on a
// table of function pointers.
#define INS_GET_VERSION 0x01
#define INS_AUTH_SIGN_TXN 0x03
#define INS_ENCRYPT_DECRYPT_MSG 0x04
#define INS_SHOW_ADDRESS 0x05
#define INS_GET_PUBLIC_KEY_AND_CHAIN_CODE 0x06
#define INS_SIGN_TOKEN 0x07

// This is the function signature for a command handler
typedef int handler_fn_t(const command_t* const cmd);

handler_fn_t getVersionHandler;
handler_fn_t authAndSignTxnHandler;
handler_fn_t encryptDecryptMessageHandler;
handler_fn_t showAddressHandler;
handler_fn_t getPublicKeyAndChainCodeHandler;
handler_fn_t signTokenMessageHandler;

// function translate command ID to function PTR
static handler_fn_t* lookupHandler(uint8_t ins) {
    switch (ins) {
        case INS_GET_VERSION:
            return getVersionHandler;
        case INS_AUTH_SIGN_TXN:
            return authAndSignTxnHandler;
        case INS_ENCRYPT_DECRYPT_MSG:
            return encryptDecryptMessageHandler;
        case INS_SHOW_ADDRESS:
            return showAddressHandler;
        case INS_GET_PUBLIC_KEY_AND_CHAIN_CODE:
            return getPublicKeyAndChainCodeHandler;
        case INS_SIGN_TOKEN:
            return signTokenMessageHandler;
        default:
            return NULL;
    }
}

static void nv_storage_init() {
    if (N_storage.initialized != true) {
        internalStorage_t storage;
        storage.settings.allowBlindSigning = false;
        storage.initialized = true;
        nvm_write((void*) &N_storage, (void*) &storage, sizeof(internalStorage_t));
    }
}

// This is the main loop that reads and writes APDUs. It receives request
// APDUs from the computer, looks up the corresponding command handler, and
// calls it on the APDU payload.
void app_main(void) {
    PRINTF("app_main, sizeof(state) = %d\n", sizeof(state));

    // Length of APDU command received in G_io_apdu_buffer
    volatile int input_len = 0;

    // Structured APDU command
    command_t cmd;

    io_init();
    nv_storage_init();
    ui_menu_main();

    // this is used to clean state if we change command types
    volatile uint8_t lastCmdNumber = 0;

    for (;;) {
        BEGIN_TRY {
            TRY {
                // Reset structured APDU command
                explicit_bzero(&cmd, sizeof(cmd));

                // Receive command bytes in G_io_apdu_buffer
                input_len = io_recv_command();
                if (input_len < 0) {
                    CLOSE_TRY;
                    return;
                }

                // Parse APDU command from G_io_apdu_buffer
                if (!apdu_parser(&cmd, G_io_apdu_buffer, input_len)) {
                    PRINTF("=> /!\\ BAD LENGTH: %.*H\n", input_len, G_io_apdu_buffer);
                    io_send_return1(R_WRONG_DATA_LENGTH);
                    CLOSE_TRY;
                    continue;
                }

                PRINTF("=> CLA=%02X | INS=%02X | P1=%02X | P2=%02X | Lc=%02X | CData=%.*H\n",
                       cmd.cla,
                       cmd.ins,
                       cmd.p1,
                       cmd.p2,
                       cmd.lc,
                       cmd.lc,
                       cmd.data);

                // Malformed APDU.
                if (cmd.cla != CLA) {
                    lastCmdNumber = 0;  // forces the next handler call to clean the state
                    io_send_return1(R_BAD_CLA);
                    CLOSE_TRY;
                    continue;
                }

                // Lookup and call the requested command handler.
                handler_fn_t* handlerFn = lookupHandler(cmd.ins);
                if (!handlerFn) {
                    lastCmdNumber = 0;  // forces the next handler call to clean the state
                    io_send_return1(R_UNKOWN_CMD);
                    CLOSE_TRY;
                    continue;
                }

                PRINTF("canary check %d last command number %d\n", check_canary(), lastCmdNumber);

                if (lastCmdNumber != cmd.ins) {
                    // last command was different, clean state
                    cleanState();
                }

                if (handlerFn(&cmd) < 0) {
                    lastCmdNumber = 0;  // forces the next handler call to clean the state
                    CLOSE_TRY;
                    continue;
                }

                lastCmdNumber = cmd.ins;
            }
            CATCH(EXCEPTION_IO_RESET) {
                THROW(EXCEPTION_IO_RESET);  // lastCmdNumber will be zero'd when app_main will be
                                            // called again
            }
            CATCH_OTHER(e) {
                lastCmdNumber = 0;
                io_send_return3(R_EXCEPTION, e >> 8, e & 0xFF);
            }
            FINALLY {
                // intentionally blank
            }
        }
        END_TRY;
    }
}
