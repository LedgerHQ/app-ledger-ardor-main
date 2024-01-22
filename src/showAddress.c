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
#include "parser.h"  // command_t

#include "returnValues.h"
#include "config.h"
#include "ardor.h"
#include "ui/menu.h"
#include "ui/display.h"
#include "io_helper.h"  // io_send_return*

void showAddressConfirm(void) {
    io_send_return1(R_SUCCESS);
    ui_menu_main();
}

void showAddressCancel(void) {
    io_send_return1(R_REJECT);
    ui_menu_main();
}

int showAddressHandler(const command_t* const cmd) {
    if (!isValidDerivationPathLength(cmd->lc)) {
        return io_send_return1(R_WRONG_SIZE_ERR);
    }

    uint16_t exception = 0;
    uint8_t publicKey[PUBLIC_KEY_SIZE];
    explicit_bzero(publicKey, sizeof(publicKey));

    // cmd->lc (derivationParamLengthInBytes) should be multiple of 4, it's checked above
    uint8_t ret = ardorKeys(cmd->data, cmd->lc / sizeof(uint32_t), 0, publicKey, 0, 0, &exception);

    if (ret == R_SUCCESS) {
        uint64_t accountId;
        if (publicKeyToId(publicKey, &accountId) != CX_OK) {
            return io_send_return1(R_CXLIB_ERROR);
        }
        showAddressScreen(accountId);
        return 0;
    } else if (ret == R_KEY_DERIVATION_EX) {
        return io_send_return3(ret, exception >> 8, exception & 0xFF);
    } else {
        return io_send_return2(R_SUCCESS, ret);
    }
}
