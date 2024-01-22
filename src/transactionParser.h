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

#include "ardor.h"

#define PARSE_FN_MAIN 1
#define PARSE_FN_APPENDAGES_FLAGS 2
#define PARSE_FN_FXT_COIN_EXCHANGE_ORDER_ISSUE_OR_COIN_EXCHANGE_ORDER_ISSUE_ATTACHMENT 4
#define PARSE_FN_ASSET_ORDER_PLACEMENT_ATTACHMENT 5
#define PARSE_FN_IGNORE_BYTES_UNTIL_THE_END 6
#define PARSE_FN_ASSET_TRANSFER_ATTACHMENT 7

// Added bytes to the read buffer
//@param newData: ptr to the data
//@param numBytes: number of bytes in the data
// return R_SUCCESS on success, R_NO_SPACE_BUFFER_TOO_SMALL othereize
uint8_t addToReadBuffer(const uint8_t* const newData, const uint8_t numBytes);

// Parses the tx from the read buffer using the parse functions from state.txnAuth.functionStack
// If there aren't enough bytes in the read buffer it returns R_SEND_MORE_BYTES
uint8_t parseTransaction(uint8_t (*setScreenTexts)());