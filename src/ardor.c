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
#include <cx.h>
#include <os_io_seproxyhal.h>

#include "ardor.h"
#include "curve25519_i64.h"
#include "returnValues.h"



//pretty much does what it says, arodorKey() return an error if the path is smaller then defined
#define MIN_DERIVATION_PATH_LENGTH 3

//the global state
states_t state;


extern unsigned long _stack;
#define STACK_CANARY (*((volatile uint32_t*) &_stack))

//todo: figure out if we're doing cannarys
void init_canary() { //todo, make a rand cannary here
    STACK_CANARY = 0xDEADBEEF;
}

bool check_canary() {
    return STACK_CANARY == 0xDEADBEEF;
}

//This is a prepocessor function for dialogs, it allows long labels to go in circles, like long crypto addresses, I have no idea how this works :)
unsigned int makeTextGoAround_preprocessor(bagl_element_t * const element)
{
    //I guess we are filtering on the UI element
    if (element->component.userid > 0)
        UX_CALLBACK_SET_INTERVAL(MAX(3000, 1000 + bagl_label_roundtrip_duration_ms(element, 7)));
    
    return 1;
}

//self explanatory
//output must point to buffer of 32 bytes in size
void sha256TwoBuffers(const uint8_t * const bufferTohash1, const uint16_t sizeOfBuffer1, const uint8_t * const bufferTohash2, const uint16_t sizeOfBuffer2, uint8_t * const output) {
    cx_sha256_t shaContext;

    os_memset(output, 0, 32);
    cx_sha256_init(&shaContext); //return value has no info

    cx_hash(&shaContext.header, 0, bufferTohash1, sizeOfBuffer1, output, 32);

    if (0 != bufferTohash2)
        cx_hash(&shaContext.header, 0, bufferTohash2, sizeOfBuffer2, output, 32);
    
    cx_hash(&shaContext.header, CX_LAST, 0, 0, output, 32);
}

//self explanatory
//output must point to buffer of 32 bytes in size
void sha256Buffer(const uint8_t * const bufferTohash, const uint16_t sizeOfBuffer, uint8_t * const output) {
    sha256TwoBuffers(bufferTohash, sizeOfBuffer, 0, 0, output);
}

//This is the EC-KCDSA siging implementation
//@param in: keySeedBfr should point to a 32 byte keyseed (privateKey ^ -1)
//@parma in: msgSha256 should point to a 32 byte sha256 of the message we are signing
//@param out: sig should point to 64 bytes allocated to hold the signiture of the message
void signMsg(const uint8_t * const keySeedBfr, const uint8_t * const msgSha256, uint8_t * const sig) {

    uint8_t publicKeyX[32], privateKey[32]; os_memset(publicKeyX, 0, sizeof(publicKeyX)); os_memset(privateKey, 0, sizeof(privateKey));

    keygen25519(publicKeyX, privateKey, keySeedBfr);

    uint8_t x[32]; os_memset(x, 0, sizeof(x));

    sha256TwoBuffers(msgSha256, 32, privateKey, sizeof(privateKey), x);

    uint8_t Y[32]; os_memset(Y, 0, sizeof(Y));

    keygen25519(Y, 0, x);

    uint8_t h[32]; os_memset(h, 0, sizeof(h));

    sha256TwoBuffers(msgSha256, 32, Y, sizeof(Y), h);

    os_memmove(sig + 32, h, 32);

    sign25519(sig, h, x, privateKey); //todo: i changed s to privateKey maybe this is a problem
}



//todo: make sure i clean everything out
//this function derives an ardor keeyseed (privatekey ^ -1), public key, ed255119 public key and chaincode

//@param in: derivationPath - a BIP42 derivation path, must be at least of length MIN_DERIVATION_PATH_LENGTH
//@param in: derivationPathLengthInUints32 - kinda what it says it is
//@param optional out: keySeedBfrOut - 64 byte EC-KCDSA keyseed for the derivation path
//@param optional out: publicKeyCurveOut - 32 byte EC-KCDSA public key for the derivation path
//@param optional out: publicKeyEd25519Out - 32 byte ED255119 public key for the derivation path (used for debuging)
//@param optional out: chainCodeOut - the 32 byte ED255119 derivation chaincode, used for external master public key derivation
//@param out: exceptionOut - iff the return code is R_EXCEPTION => exceptionOut will be filled with the Nano exception code
//@returns: regular return values

uint8_t ardorKeys(const uint32_t * const derivationPath, const uint8_t derivationPathLengthInUints32, 
                    uint8_t * const keySeedBfrOut, uint8_t * const publicKeyCurveOut, uint8_t * const publicKeyEd25519Out, uint8_t * const chainCodeOut, uint16_t * const exceptionOut) {
    
    uint8_t publicKeyBE[32]; os_memset(publicKeyBE, 0, sizeof(publicKeyBE)); //declaring here although used later, so it can be acessable to the finally statement
    uint8_t keySeedBfr[64]; os_memset(keySeedBfr, 0, sizeof(keySeedBfr));
    struct cx_ecfp_256_private_key_s privateKey; //Don't need to init, since the ->d is copied into from some other palce

    uint32_t bipPrefix[] = PATH_PREFIX; //defined in Makefile

    if ((derivationPathLengthInUints32 < sizeof(bipPrefix) / sizeof(bipPrefix[0])) || (derivationPathLengthInUints32 < MIN_DERIVATION_PATH_LENGTH))
        return R_DERIVATION_PATH_TOO_SHORT;

    for (uint8_t i = 0; i < sizeof(bipPrefix) / sizeof(bipPrefix[0]); i++) {
        if (derivationPath[i] != bipPrefix[i])
            return R_WRONG_DERIVATION_PATH_HEADER;
    }

    BEGIN_TRY {
            TRY {
                    //todo: understand that in BLUE only has SLIP10, and document this 
                    os_perso_derive_node_bip32(CX_CURVE_Ed25519, derivationPath, derivationPathLengthInUints32, keySeedBfr, chainCodeOut);

                    // weird custom initilization, code copied from Cardano's EdDSA implementaion
                    privateKey.curve = CX_CURVE_Ed25519;
                    privateKey.d_len = 64;
                    os_memmove(privateKey.d, keySeedBfr, 32);
                    

                    if (0 != keySeedBfrOut)
                        os_memmove(keySeedBfrOut, keySeedBfr, 64); //the first of 32 bytes are used //todo, put back 64

                    //uint8_t P[32], s[32]; os_memset(P, 0, 32); os_memset(s, 0, 32);

                    //keygen25519(P, s, keySeedBfr);

                    //PRINTF("\nCurvedPrivateKey = publicKey (Genereated to check against) = %.*H", 32, P);
                    
                    if ((0 != publicKeyCurveOut) || (0 != publicKeyEd25519Out)) { //todo check that the private keys still gets loaded if not generate_pair

                        cx_ecfp_public_key_t publicKey; 
                        cx_ecfp_init_public_key(CX_CURVE_Ed25519, 0, 0, &publicKey);

                        //cx_ecfp_generate_pair(CX_CURVE_Ed25519, &publicKey, &privateKey, 0);

                        cx_eddsa_get_public_key(
                                // cx_eddsa has a special case struct for Cardano's private keys
                                // but signature is standard
                                &privateKey,
                                CX_SHA512,
                                &publicKey,
                                NULL, 0, NULL, 0);


                        // copy public key from big endian to little endian
                        for (uint8_t i = 0; i < sizeof(publicKeyBE); i++) {
                            publicKeyBE[i] = publicKey.W[64 - i];
                        }

                        //PRINTF("\nd4");

                        //todo figure out if we need this
                        /*
                        // set sign bit
                        if ((publicKey.W[32] & 1) != 0) {
                            publicKeyBE[31] |= 0x80;
                        }
                        */
                        

                        //todo figure out the bit signing thing?

                        if (0 != publicKeyEd25519Out)
                            os_memmove(publicKeyEd25519Out, publicKeyBE, 32);


                        if (0 != publicKeyCurveOut)
                            morph25519_e2m(publicKeyCurveOut, publicKeyBE);                      
                    }
            }
            CATCH_OTHER(exception) {
                *exceptionOut = exception;
                return R_KEY_DERIVATION_EX;
            }
            FINALLY {

                os_memset(privateKey.d, 0, privateKey.d_len);
                os_memset(keySeedBfr, 0, sizeof(keySeedBfr));
                os_memset(publicKeyBE, 0, sizeof(publicKeyBE));
            }
        }
        END_TRY;
    
    return R_SUCCESS;
}

//todo, figure out what the real size of the keyseed is
//Creates a shared AES encryption key one the matches the key related to the derivation path, the target public key and the nonce
//@param in: derivationPath                     - the derivation path
//@param in: derivationPathLengthInUints32      - kinda clear what this is
//@param in: targetPublicKey                    - the 32 byte public key
//@param out: aesKeyOut                         - the shared encryption key 32 bytes
//@param out: addressIdOut                      - the address id related to the derivation path on the ledger

uint8_t getSharedEncryptionKey(const uint32_t * const derivationPath, const uint8_t derivationPathLengthInUints32, const uint8_t* const targetPublicKey, 
                                const uint8_t * const nonce, uint16_t * const exceptionOut, uint8_t * const aesKeyOut, uint64_t * const addressIdOut) {
    
    uint8_t keySeed[64]; os_memset(keySeed, 0, sizeof(keySeed));

    uint8_t ret = ardorKeys(derivationPath, derivationPathLengthInUints32, keySeed, 0, 0, 0, exceptionOut);

    if (R_SUCCESS != ret)
        return ret;

    *addressIdOut = publicKeyToId(keySeed);

    uint8_t sharedKey[32]; os_memset(sharedKey, 0, sizeof(sharedKey));


    curve25519(sharedKey, keySeed, targetPublicKey); //should use only the first 32 bytes of keyseed
    
    for (uint8_t i = 0; i < sizeof(sharedKey); i++)
        sharedKey[i] ^= nonce[i];

    sha256Buffer(sharedKey, sizeof(sharedKey), aesKeyOut);

    return R_SUCCESS;
}

//param: publicKey should point to a 32 byte public key buffer
//returns: a 64bit public key id, used later with reedsolomon to create Ardor/NXT addresses
uint64_t publicKeyToId(const uint8_t * const publicKey) {
        
    uint8_t tempSha[32];
    sha256Buffer(publicKey, 32, tempSha);

    return ((((uint64_t) tempSha[7]) << 56) |
            (((uint64_t) tempSha[6]) << 48) |
            (((uint64_t) tempSha[5]) << 40) |
            (((uint64_t) tempSha[4]) << 32) |
            (((uint64_t) tempSha[3]) << 24) |
            (((uint64_t) tempSha[2]) << 16) |
            (((uint64_t) tempSha[1]) << 8) |
            (((uint64_t) tempSha[0] )));
}
