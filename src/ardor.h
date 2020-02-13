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

uint64_t publicKeyToId(const uint8_t * const publicKey);
uint8_t ardorKeys(const uint32_t * derivationPath, const uint8_t derivationPathLengthInUints32, 
                            uint8_t *keySeedBfrOut, uint8_t *publicKeyCurveOut, uint8_t * publicKeyEd25519Out, uint8_t * chainCodeOut, uint16_t * exceptionOut);

bool check_canary();

#define FUNCTION_STACK_SIZE 30
#define IV_SIZE 16

//todo add comments to all the structs here
typedef struct {

	bool txnPassedAutherization;

    uint8_t readBuffer[512];
    uint16_t readBufferEndPos;
    uint16_t readBufferReadOffset;
    uint16_t numBytesRead;

    uint8_t functionStack[FUNCTION_STACK_SIZE];
    uint8_t numFunctionsOnStack;

    bool isClean;


    uint8_t displayTitle[64];
    uint8_t displaystate[130]; //todo dont know if this is the best, maybe we can make it shorter?

    
    uint8_t tempBuffer[32];
    
    cx_sha256_t hashstate;
    uint8_t finalHash[32];

    uint32_t chainId;
    uint16_t transactionTypeAndSubType; //todo rename all of these to txn
    uint8_t txnTypeIndex;

    uint8_t version;
    uint64_t recipientId;
    uint64_t amount;
    uint64_t fee;
    uint32_t appendagesFlags;
    
    uint8_t displayType;
    int8_t dialogScreenIndex;


   	int32_t attachmentTempInt32Num1, attachmentTempInt32Num2;
   	int64_t attachmentTempInt64Num1, attachmentTempInt64Num2, attachmentTempInt64Num3;

   	uint16_t txnSizeBytes;

} authTxn_t;

typedef struct {
    uint8_t mode;
    uint8_t state;
    uint8_t cbc[16];
    unsigned long ctx[4 * 4 * 15 + 4];

    uint8_t sharedKey[32]; //is used only in the case of P1_INIT_DECRYPT_SHOW_SHARED_KEY, the key is put aside here, until it is autherized to be shared by the dialog
                           //should be cleaned to 0 when possible


    uint8_t nonce[32];


    uint16_t messageLengthBytes;
    uint8_t dialogTitle[32];
    uint8_t dialogContent[110]; //Should be able to hold: 65535 bytes between your ARDOR-AXL8-9PF8-UQTF-CWB92 and ARDOR-AXL8-9PF8-UQTF-CWB92 and share encryption key
                             //Note: if you change the ARDOR prefix to something longer, then you need to lengthen this array

} encyptionState_t;

typedef struct {
    uint8_t mode;
    cx_sha256_t hashstate;
} signTokenState_t;

//todo make sure to add some more mode state varible, to make sure the union isn't taken advantage off
typedef union {
    encyptionState_t encryption;
    authTxn_t txnAuth;
    signTokenState_t tokenCreation;
} states_t;

extern states_t state;

typedef struct {
    uint16_t id;
    char * name;
    uint8_t attachmentParsingFunctionNumber;
} txnType;

void initTxnAuthState(); //this cleans the atuhTxn part of the state
void cleanSharedState();

//These to are automaticly generated by createTxnTypes.py into src/txnTypeLists.c
extern const txnType TXN_TYPES[];
extern const uint8_t LEN_TXN_TYPES;
unsigned int makeTextGoAround_preprocessor(bagl_element_t * const element);
