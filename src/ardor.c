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
#include <cx.h>

#include "curve25519_i64.h"
#include "returnValues.h"
#include "config.h"

#include "ardor.h"

// the global state
states_t state;

// persistent storage: app settings
const internalStorage_t N_storage_real;

void cleanState() {
    explicit_bzero(&state, sizeof(state));
}

// SHA-256 of two buffers, the output is the hash of the concatenation of the two buffers
//@param[in] bufferTohash1 - first buffer to hash
//@param[in] sizeOfBuffer1 - size of first buffer to hash
//@param[in] bufferTohash2 - second buffer to hash
//@param[in] sizeOfBuffer2 - size of second buffer to hash
//@param[out] output - 32 byte buffer to hold the hash
// return crypto library error code (CX_OK if success)
static cx_err_t sha256TwoBuffers(const uint8_t *const bufferTohash1,
                                 const uint16_t sizeOfBuffer1,
                                 const uint8_t *const bufferTohash2,
                                 const uint16_t sizeOfBuffer2,
                                 uint8_t *const output) {
    cx_sha256_t shaContext;

    explicit_bzero(output, 32);
    cx_err_t rc = cx_sha256_init_no_throw(&shaContext);  // return value has no info
    if (rc != CX_OK) {
        return rc;
    }

    rc = cx_hash_no_throw(&shaContext.header, 0, bufferTohash1, sizeOfBuffer1, output, 32);
    if (rc != CX_OK) {
        return rc;
    }

    if (bufferTohash2 != 0) {
        rc = cx_hash_no_throw(&shaContext.header, 0, bufferTohash2, sizeOfBuffer2, output, 32);
        if (rc != CX_OK) {
            return rc;
        }
    }

    return cx_hash_no_throw(&shaContext.header, CX_LAST, 0, 0, output, 32);
}

// SHA-256 of a single buffer
//@param[in] in - buffer to hash
//@param[in] len - length of buffer to hash
//@param[out] out - 32 byte buffer to hold the hash
// return crypto library error code (CX_OK if success)
static cx_err_t sha256Buffer(const uint8_t *const in, const uint16_t len, uint8_t *const out) {
    return sha256TwoBuffers(in, len, 0, 0, out);
}

// This is the EC-KCDSA siging implementation
//@param[in] keySeedBfr should point to a 32 byte keyseed (privateKey ^ -1) - note this function can
//           edit keySeedBfr in the process
//@param[in] msgSha256 should point to a 32 byte sha256 of the message we are signing
//@param[out] sig should point to 64 bytes allocated to hold the signiture of the message
// return crypto library error code (CX_OK if success)
cx_err_t signMsg(uint8_t *const keySeedBfr, const uint8_t *const msgSha256, uint8_t *const sig) {
    uint8_t publicKeyX[32], privateKey[32];
    explicit_bzero(publicKeyX, sizeof(publicKeyX));
    explicit_bzero(privateKey, sizeof(privateKey));

    keygen25519(publicKeyX, privateKey, keySeedBfr);

    uint8_t x[32];
    explicit_bzero(x, sizeof(x));

    cx_err_t err = sha256TwoBuffers(msgSha256, 32, privateKey, sizeof(privateKey), x);
    if (err != CX_OK) {
        return err;
    }

    uint8_t Y[32];
    explicit_bzero(Y, sizeof(Y));

    keygen25519(Y, 0, x);

    uint8_t h[32];
    explicit_bzero(h, sizeof(h));

    err = sha256TwoBuffers(msgSha256, 32, Y, sizeof(Y), h);
    if (err != CX_OK) {
        return err;
    }

    memmove(sig + 32, h, 32);

    sign25519(sig, h, x, privateKey);

    // clean buffers
    explicit_bzero(privateKey, sizeof(privateKey));
    explicit_bzero(x, sizeof(x));
    explicit_bzero(Y, sizeof(Y));
    explicit_bzero(h, sizeof(h));

    return CX_OK;
}

// from curveConversion.C
void morph25519_e2m(uint8_t *montgomery, const uint8_t *y);

// Derives an ardor keyseed (privatekey ^ -1), public key, ed255119 public key and chaincode.
// For more info on how this derivation works, please read the readme.
//@param[in] derivationPath a BIP42 derivation path, must be at least of length
//           MIN_DERIVATION_PATH_LENGTH
//@param[in] derivationPathLengthInUints32 - kinda what it says it is
//@param[out] keySeedBfrOut (optional) 32 byte EC-KCDSA keyseed for the derivation path
//@param[out] publicKeyCurveXout (optional) 32 byte EC-KCDSA public key for the derivation path
//@param[out] publicKeyEd25519YLEWithXParityOut (optional) 32 byte ED255119 public key for the
//            derivation path (used for debuging), with the MSB as X's parity
//@param[out] chainCodeOut (optional) the 32 byte ED255119 derivation chaincode, used for external
//            master public key derivation
//@param[out] exceptionOut iff the return code is R_KEY_DERIVATION_EX => exceptionOut will be filled
//            with error code (type cx_err_t, just the 16 LSBs)
//@returns: regular return values
uint8_t ardorKeys(const uint8_t *const derivationPath,
                  const uint8_t derivationPathLengthInUints32,
                  uint8_t *const keySeedBfrOut,
                  uint8_t *const publicKeyCurveXout,
                  uint8_t *const publicKeyEd25519YLEWithXParityOut,
                  uint8_t *const chainCodeOut,
                  uint16_t *const exceptionOut) {
    uint32_t bipPrefix[] = PATH_PREFIX;  // defined in Makefile

    if (derivationPathLengthInUints32 < MIN_DERIVATION_LENGTH ||
        (derivationPathLengthInUints32 > MAX_DERIVATION_LENGTH))
        return R_WRONG_SIZE_ERR;

    // os_derive_bip32_no_throw doesn't accept derivation paths located on the input buffer, so we
    // make a local stack copy
    uint32_t copiedDerivationPath[MAX_DERIVATION_LENGTH];
    explicit_bzero(copiedDerivationPath, sizeof(copiedDerivationPath));
    memmove(copiedDerivationPath, derivationPath, derivationPathLengthInUints32 * sizeof(uint32_t));

    for (uint8_t i = 0; i < sizeof(bipPrefix) / sizeof(bipPrefix[0]); i++) {
        if (bipPrefix[i] != copiedDerivationPath[i]) {
            return R_WRONG_DERIVATION_PATH_HEADER;
        }
    }

    uint8_t KLKR[64];
    explicit_bzero(KLKR, sizeof(KLKR));
    cx_err_t ret = os_derive_bip32_no_throw(CX_CURVE_Ed25519,
                                            copiedDerivationPath,
                                            derivationPathLengthInUints32,
                                            KLKR,
                                            chainCodeOut);
    if (ret != CX_OK) {
        explicit_bzero(KLKR, sizeof(KLKR));
        *exceptionOut = (uint16_t) ret;
        return R_KEY_DERIVATION_EX;
    }

    // weird custom initilization, code copied from Cardano's EdDSA implementaion
    struct cx_ecfp_256_extended_private_key_s privateKey;
    privateKey.curve = CX_CURVE_Ed25519;
    privateKey.d_len = 64;
    memmove(privateKey.d, KLKR, 64);

    // KL is the keyseed, KR is used for key derivation
    if (keySeedBfrOut != 0) {
        memmove(keySeedBfrOut, KLKR, 32);
    }

    if ((publicKeyCurveXout != 0) || (publicKeyEd25519YLEWithXParityOut != 0)) {
        cx_ecfp_public_key_t publicKey;
        ret = cx_ecfp_init_public_key_no_throw(CX_CURVE_Ed25519, 0, 0, &publicKey);
        if (ret != CX_OK) {
            explicit_bzero(privateKey.d, sizeof(privateKey.d));
            explicit_bzero(KLKR, sizeof(KLKR));
            *exceptionOut = (uint16_t) ret;
            return R_KEY_DERIVATION_EX;
        }

        // This should return A = KL * B (B is the generator point in ED25519)
        // So publicKey.W = 04 Ax Ay in BE
        ret =
            cx_eddsa_get_public_key_no_throw((const struct cx_ecfp_256_private_key_s *) &privateKey,
                                             CX_SHA512,
                                             &publicKey,
                                             NULL,
                                             0,
                                             NULL,
                                             0);
        if (ret != CX_OK) {
            explicit_bzero(privateKey.d, sizeof(privateKey.d));
            explicit_bzero(KLKR, sizeof(KLKR));
            *exceptionOut = (uint16_t) ret;
            return R_KEY_DERIVATION_EX;
        }

        // copy public key from big endian to little endian
        uint8_t publicKeyYLE[32];
        explicit_bzero(publicKeyYLE, sizeof(publicKeyYLE));
        for (uint8_t i = 0; i < sizeof(publicKeyYLE); i++) {
            publicKeyYLE[i] = publicKey.W[64 - i];
        }

        if (publicKeyCurveXout != 0) {
            morph25519_e2m(publicKeyCurveXout, publicKeyYLE);
        }

        // We encode the parity of X into the MSB of Y, since it's never used because of the field
        // size This allows us to compress X,Y into 32 bytes
        if ((publicKey.W[32] & 1) != 0) {
            publicKeyYLE[31] |= 0x80;
        }

        if (publicKeyEd25519YLEWithXParityOut != 0) {
            memmove(publicKeyEd25519YLEWithXParityOut, publicKeyYLE, 32);
        }

        explicit_bzero(publicKeyYLE, sizeof(publicKeyYLE));
    }

    explicit_bzero(privateKey.d, sizeof(privateKey.d));
    explicit_bzero(KLKR, sizeof(KLKR));

    return R_SUCCESS;
}

// Creates a shared AES encryption key one the matches the key related to the derivation path, the
// target public key and the nonce
//@param derivationPath - the derivation path
//@param derivationPathLengthInUints32 - kinda clear what this is
//@param targetPublicKey - the 32 byte public key
uint8_t getSharedEncryptionKey(const uint8_t *const derivationPath,
                               const uint8_t derivationPathLengthInUints32,
                               const uint8_t *const targetPublicKey,
                               const uint8_t *const nonce,
                               uint16_t *const exceptionOut,
                               uint8_t *const aesKeyOut) {
    uint8_t keySeed[32];
    explicit_bzero(keySeed, sizeof(keySeed));

    uint8_t ret =
        ardorKeys(derivationPath, derivationPathLengthInUints32, keySeed, 0, 0, 0, exceptionOut);

    if (ret != R_SUCCESS) {
        return ret;
    }

    uint8_t sharedKey[32];
    explicit_bzero(sharedKey, sizeof(sharedKey));

    curve25519(sharedKey, keySeed, targetPublicKey);  // should use only the first
                                                      // 32 bytes of keySeed
    for (uint8_t i = 0; i < sizeof(sharedKey); i++) {
        sharedKey[i] ^= nonce[i];
    }

    if (sha256Buffer(sharedKey, sizeof(sharedKey), aesKeyOut) != CX_OK) {
        return R_CXLIB_ERROR;
    }

    // clean up buffers
    explicit_bzero(keySeed, sizeof(keySeed));
    explicit_bzero(sharedKey, sizeof(sharedKey));

    return R_SUCCESS;
}

// Computes the 64bit account id from a given public key
//@param publicKey - the 32 byte public key
//@param accountIdOut - pointer to store the computed account ID
cx_err_t publicKeyToId(const uint8_t *const publicKey, uint64_t *const accountIdOut) {
    uint8_t hashOut[32];
    cx_err_t err = sha256Buffer(publicKey, 32, hashOut);
    if (err != CX_OK) {
        return err;
    }

    // Extract the account ID from the first 8 bytes of the hash
    // Assuming little-endian architecture
    *accountIdOut = *((uint64_t *) hashOut);

    return CX_OK;
}

/**
 * Checks if the given derivation path length is valid.
 * A valid length is a multiple of 4 bytes (sizeof(uint32_t)) and within the range of
 * MIN_DERIVATION_LENGTH and MAX_DERIVATION_LENGTH (inclusive).
 *
 * @param length The length of the derivation path in bytes.
 * @return true if the length is valid, false otherwise.
 */
bool isValidDerivationPathLength(uint8_t length) {
    return length >= MIN_DERIVATION_LENGTH * sizeof(uint32_t) &&
           length <= MAX_DERIVATION_LENGTH * sizeof(uint32_t) && length % sizeof(uint32_t) == 0;
}

// returns the chain name for a given chainId
char *chainName(const uint8_t chainId) {
    return (char *) PIC(((chainType *) PIC(&CHAINS[chainId - 1]))->name);
}

// the amount of digits on the right of the decimal dot for each chain
uint8_t chainNumDecimalsBeforePoint(const uint8_t chainId) {
    return ((chainType *) PIC(&CHAINS[chainId - 1]))->numDecimalsBeforePoint;
}

// this function formats amounts into string and most importantly add the dot where it's supposed to
// be the way this is works is that amounts ints and then the dot is added after
// chainNumDecimalsBeforePoint() digits from right to left for example, if the amount is 4200000000
// and we are in the Ardor chain in which chainNumDecimalsBeforePoint() is 8 then the formated
// amount will be "42" for 4210100000 it will be 42.101
//@param outputString - does what it says
//@param maxOutputLength - does what it says
//@param numberToFormat - the input number to format, isn't const cuz we play with it in order to
// format the number
//@param numDigitsBeforeDecimal - read first paragraph for info
//@returns 0 iff some kind of error happend, else the length of the output string including the null
// terminator
uint8_t formatAmount(char *const outputString,
                     const uint16_t maxOutputLength,
                     uint64_t numberToFormat,
                     const uint8_t numDigitsBeforeDecimal) {
    uint16_t outputIndex = 0;
    bool wasANumberWritten = false;
    bool isDotWritten = false;
    uint8_t numberIndex = 0;

    while (true) {
        uint8_t modulo = numberToFormat % 10;
        numberToFormat -= modulo;
        numberToFormat /= 10;

        if (numberIndex == numDigitsBeforeDecimal) {
            if (wasANumberWritten && (!isDotWritten) && (numDigitsBeforeDecimal != 0)) {
                isDotWritten = true;
                outputString[outputIndex++] = '.';
            }

            wasANumberWritten = true;
        }

        if (0 != modulo) {
            wasANumberWritten = true;
        }

        if (wasANumberWritten || (numDigitsBeforeDecimal == 0)) {
            outputString[outputIndex++] = '0' + modulo;
        }

        if (outputIndex >= maxOutputLength) {
            return 0;
        }

        if ((numberToFormat == 0) && (numberIndex >= numDigitsBeforeDecimal)) {
            break;
        }

        numberIndex++;
    }

    // reverse the string since we are creating it from left to right, and numbers are right to left
    for (uint16_t i = 0; i < outputIndex - 1 - i; i++) {
        uint8_t temp = outputString[i];
        outputString[i] = outputString[outputIndex - i - 1];
        outputString[outputIndex - i - 1] = temp;
    }

    outputString[outputIndex] = 0;
    return outputIndex + 1;
}

// like formatAmount but also appends the chain (token) name
uint8_t formatChainAmount(char *const out,
                          const uint16_t maxLength,
                          uint64_t amount,
                          const uint8_t chainId) {
    uint8_t ret = formatAmount(out, maxLength, amount, chainNumDecimalsBeforePoint(chainId));
    if (ret == 0) {
        return 0;
    }

    // append an space and the chain name
    snprintf(out + ret - 1, maxLength - ret - 1, " %s", chainName(chainId));

    return ret + strlen(chainName(chainId)) + 1;
}

// app_stack_canary is defined by the link script to be at the start of the user data or end of the
// stack, something like that so if there is a stack overflow then it will be overwriten, this is
// how check_canary() works. make sure HAVE_BOLOS_APP_STACK_CANARY is defined in the makefile, so
// that the OS code will init it and check against it every io_exchange call if the canary is not
// the same, and if not, it will throw

extern unsigned int app_stack_canary;

bool check_canary() {
    return 0xDEAD0031 == app_stack_canary;
}
