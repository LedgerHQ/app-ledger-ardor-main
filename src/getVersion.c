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

#include "io.h"          // io_send*
#include "parser.h"      // command_t
#include "os_helpers.h"  // UNUSED

#include "config.h"
#include "returnValues.h"

// function that returns the version, in order to see if this is actually the ardor app
// returns VERSION 3 bytes | FLAGS 1 byte | ARDOR_SPECIAL_IDENTIFIER 3 bytes
int getVersionHandler(const command_t *const cmd) {
    UNUSED(cmd);

    uint8_t data[7];
    data[0] = APPVERSION_M;
    data[1] = APPVERSION_N;
    data[2] = APPVERSION_P;
    data[3] = VERSION_FLAGS;
    memmove(data + 4, ARDOR_SPECIAL_IDENTIFIER, ARDOR_SPECIAL_IDENTIFIER_LEN);
    return io_send_response_pointer((const uint8_t *) data,
                                    4 + ARDOR_SPECIAL_IDENTIFIER_LEN,
                                    SW_OK);
}
