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

#define SW_OK 0x9000

enum returnValues {
    R_SUCCESS = 0,
    R_REJECT = 1,
    R_BAD_CLA = 2,
    R_UNKOWN_CMD = 3,
    R_FUNCTION_STACK_FULL = 4,
    R_NO_SPACE_BUFFER_TOO_SMALL = 5,
    R_PARSE_FUNCTION_NOT_FOUND = 6,
    R_NOT_ALL_BYTES_READ = 7,
    R_FINISHED = 8,
    R_WRONG_DATA_LENGTH = 9,
    R_WRONG_DERIVATION_PATH_HEADER = 10,
    R_KEY_DERIVATION_EX = 11,
    R_FORMAT_AMOUNT_ERR = 12,
    R_FORMAT_FEE_ERR = 13,
    R_SHOW_DISPLAY = 14,
    R_SEND_MORE_BYTES = 15,
    R_UNSUPPORTED_APPENDAGE = 16,
    R_BAD_CHAIN_ID_ERR = 17,
    R_WRONG_VERSION_ERR = 18,
    R_WRONG_SIZE_ERR = 19,
    R_ERR_NO_INIT_CANT_CONTINUE = 20,
    R_NOT_ALL_BYTES_USED = 21,
    R_TXN_UNAUTHORIZED = 22,
    R_UNKNOWN_CMD_PARAM_ERR = 23,
    R_BAD_NUM_KEYS = 24,
    R_EXCEPTION = 25,
    R_DATA_BUFFER_TOO_BIG = 27,
    R_WRONG_SIZE_MODULO_ERR = 28,
    R_UNSUPPORTED_ATTACHMENT_VERSION = 29,
    R_TXN_SIZE_TOO_SMALL = 30,
    R_AES_ERROR = 31,
    R_NO_SETUP = 32,
    R_NOT_ENOUGH_DERIVATION_INDEXES = 33,
    R_WRONG_STATE = 34,
    R_CXLIB_ERROR = 35
};