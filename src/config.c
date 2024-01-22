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

// This file holds most of the CONSTANTS used in the APP
// TXN_TYPES is configured in txnTypesList.c, it's there cuz the list is auto-generated from some
// other java file in order to sync between projects

#include <stdint.h>
#include <stdbool.h>

#include "config.h"

// This configures the supported chain types, chainId, name and amount of decimals to the right of
// the point
// Some chains are no longer supported, but are kept here as the array index is used in the code
const chainType CHAINS[] = {{0x00000001, "ARDR", 8},
                            {0x00000002, "IGNIS", 8},
                            {0x00000003, "AEUR", 4},  // no longer used
                            {0x00000004, "BITS", 8},
                            {0x00000005, "MPG", 8},  // no longer used
                            {0x00000006, "GPS", 4}};
const uint8_t NUM_CHAINS = sizeof(CHAINS) / sizeof(CHAINS[0]);

const uint8_t SUPPORTED_TXN_VERSION = 1;

const appendageType APPENDAGE_TYPES[] = {{"Message"},
                                         {"EncryptedMsg"},
                                         {"NoteToSelf"},
                                         {"PrunableMessage"},
                                         {"PrunableEncMsg"},
                                         {"PublicKeyAnnoun"},
                                         {"Phasing"}};
const uint8_t NUM_APPENDAGE_TYPES = sizeof(APPENDAGE_TYPES) / sizeof(APPENDAGE_TYPES[0]);

const uint8_t ARDOR_SPECIAL_IDENTIFIER[] = {0xba, 0xbe, 0x00};
const uint8_t ARDOR_SPECIAL_IDENTIFIER_LEN = sizeof(ARDOR_SPECIAL_IDENTIFIER);

const uint8_t VERSION_FLAGS = 0x00;
