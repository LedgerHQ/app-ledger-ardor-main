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

#include <os.h>
#include <string.h>

#define BASE_32_LENGTH 13
#define BASE_10_LENGTH 20
#define CODEWORD_LENGTH 17

static const uint8_t codeword_map[] = {3, 2, 1, 0, 7, 6, 5, 4, 13, 14, 15, 16, 12, 8, 9, 10, 11};
static const char alphabet[] = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
static const uint8_t gexp[] = {1,  2,  4, 8, 16, 5,  10, 20, 13, 26, 17, 7,  14, 28, 29, 31,
                               27, 19, 3, 6, 12, 24, 21, 15, 30, 25, 23, 11, 22, 9,  18, 1};
static const uint8_t glog[] = {0, 0,  1,  18, 2, 5,  19, 11, 3,  29, 6, 27, 20, 8,  12, 23,
                               4, 10, 30, 17, 7, 22, 28, 26, 21, 25, 9, 16, 13, 14, 24, 15};

uint8_t gmult(const uint8_t a, const uint8_t b) {
    if ((a == 0) || (b == 0)) {
        return 0;
    }

    uint8_t idx = ((*(uint8_t*) PIC(&glog[a])) + (*(uint8_t*) PIC(&glog[b]))) % 31;
    return (*(uint8_t*) PIC(&gexp[idx]));
}

//@inp in - the buffer to encode, it's not const, cuz it's edited while converting
//@output out - output should be of length 21;
void reedSolomonEncode(uint64_t inp, char* const output) {
    uint8_t plain_string_32[CODEWORD_LENGTH];
    explicit_bzero(plain_string_32, CODEWORD_LENGTH);

    uint8_t index = 0;

    while (inp != 0) {
        uint8_t ret = inp % 32;
        plain_string_32[index++] = ret;
        inp -= ret;
        inp /= 32;
    }

    uint8_t p[] = {0, 0, 0, 0};
    for (int8_t i = BASE_32_LENGTH - 1; i >= 0; i--) {
        uint8_t fb = plain_string_32[i] ^ p[3];
        p[3] = p[2] ^ gmult(30, fb);
        p[2] = p[1] ^ gmult(6, fb);
        p[1] = p[0] ^ gmult(9, fb);
        p[0] = gmult(17, fb);
    }

    memcpy(plain_string_32 + BASE_32_LENGTH, p, CODEWORD_LENGTH - BASE_32_LENGTH);

    uint8_t stringIndex = 0;

    for (uint8_t i = 0; i < 17; i++) {
        uint8_t codework_index = (*(uint8_t*) PIC(&codeword_map[i]));
        uint8_t alphabet_index = plain_string_32[codework_index];
        output[stringIndex++] = (*(uint8_t*) PIC(&alphabet[alphabet_index]));

        if ((i & 3) == 3 && i < 13) {
            output[stringIndex++] = '-';
        }
    }

    output[stringIndex++] = 0;
}
