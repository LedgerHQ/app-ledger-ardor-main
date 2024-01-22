# Ledger App for Ardor

This is the official [Ardor](https://www.jelurida.com/ardor) ledger wallet app for the Ledger Nano S and X devices

## Documentation

[Ardor Wiki](https://ardordocs.jelurida.com/Connect_Ledger_Nano_S_or_Nano_X_to_your_Ardor_Wallet), [Ledger Developers Portal](https://developers.ledger.com/)

## Developer Resources

### Building using the Ledger Application Builder docker image

The `ledger-app-builder` docker image is not currently published so you will need to [fetch and build it manually](https://github.com/LedgerHQ/ledger-app-builder#standard-build). You only need to do this once and the image will be cached on your system.

Then you can switch to this repository and launch the `ledger-app-builder` docker image to build the Ardor app. Just follow the [standard instructions](https://github.com/LedgerHQ/ledger-app-builder#compile-your-app-in-the-container). In a nutshell:

    $ docker run --rm -ti -v "$(realpath .):/app" ledger-app-builder:latest
    root@656be163fe84:/app# make

### Functional tests

Functional tests are written using the Ragger framework. The tests are located in the `tests` folder.

#### Install ragger and dependencies

    pip install --extra-index-url https://test.pypi.org/simple/ -r requirements.txt
    sudo apt-get update && sudo apt-get install qemu-user-static

#### Run tests

To run all tests just issue the following command:

    pytest --device all -v --tb=short tests/

Please note you need all the different versions compiled. You can compile them all by running the helper script `./make-all` inside the docker build image.

### End to end tests

End to end tests are run from an Ardor node and the Speculos emulator. The Ardor node has some unit tests that use the Speculos emulator to test the Ledger app. Those tests also use the Speculos API to assert screen texts and send button press commands.

These tests require Docker (or a local Speculos installation) and Java 8 or newer.

To run the tests you need to build the app, load it into the Speculos emulator and run the tests from the Ardor node.

1. Build the Ledger app.
2. Run the app on the Speculos emulator using Docker. As an alternative you can use a locally installed Speculos emulator. In this case you will need to run the emulator on port 9999 and the API server on port 5000. The following command will run the emulator on Docker:

    docker run --rm -it -v $(pwd):/speculos/apps -p 9999:9999 -p 5000:5000 ghcr.io/ledgerhq/speculos --display headless --seed "opinion change copy struggle town cigar input kit school patient execute bird bundle option canvas defense hover poverty skill donkey pottery infant sense orchard" --model nanos apps/bin/app.elf

3. Clone the Ardor node repository with the Ledger unit tests: `git clone https://sargue@bitbucket.org/sargue/ardor-ledger-test.git`
4. Run tests: `./run-unit-tests.sh com.jelurida.ardor.integration.wallet.ledger.application.LedgerSpeculosSuite`

### Enable Log Messages

To turn on logging on the Ledger app

1. Install the [debug firmware](https://developers.ledger.com/docs/nano-app/debug/)
2. Enable debugging in the makefile (DEVEL = 1) - make sure not to commit this change
3. Execute `make clean` and then `make load` to generate the source code for all the PRINTF statements

### Switch Between Target Builds

In order to build the Nano S or Nano X version you just need to make sure the `BOLOS_SDK` environment variable points to the corresponding SDK.

Make sure you rebuild the whole project when switching SDKs by executing `make clean` and then `make load`.

For example to build for the Nano X the compile command would be `BOLOS_SDK=$NANOX_SDK make`

### Avoid Numeric Underflow

Be careful not to underflow unsigned numeric types, for example:

`n = (dataLength - 32) / sizeof(uint32_t);`

This line would underflow in case the `dataLength` variable is smaller than 32 which might lead to disaster
so please review carefully all substraction operations.

### Zero Tolerance for Compilation Warnings

Ledger requires no compilation warnings anywhere in the code.

It's also required to pass the Clang static analyzer. The analyzer is included on the `ledger-app-builder` docker image so, once there, you just issue the following commands:

    make clean
    scan-build --use-cc=clang -analyze-headers -enable-checker security -enable-checker unix -enable-checker valist -o scan-build --status-bugs make default

### CI using Github Actions

The project uses Github Actions to run the Clang static analyzer and the unit tests on each commit and pull request.

The CI is configured on the `.github/workflows/ci-workflow.yml` with inspiration from the [`app-boilerplate`](https://github.com/LedgerHQ/app-boilerplate) and the [`app-xrp`](https://github.com/LedgerHQ/app-xrp).

### More Code Design

Do not include project header files inside other project header files to prevent complicating the dependencies.

Store constants and hardcoded values in config.h and config.c

### Transaction Types

The `txnTypesList.c` source file is autogenerated by the `createTxnTypes.py` script from the `txtypes.txt` file. This step is automatically handled by the makefile.

`txtypes.txt` should be generated externally by the Ardor developers whenever they add a new transaction type.

Changes to the `txtypes.txt` should be picked up by the make process and a new `txnTypesList.c` automatically generated. The `txnTypesList.c` is not deleted on `make clean` but you can use `make realclean` that cleans everything.

### Code Flow

The code flow starts at `app_main` which uses a global try/catch to prevent the app from crashing on error.
The code loops on `io_recv_command` waiting for the next command buffer, then calling the appropriate handler function implemented in the different .c files.

## APDU Protocol

Commands are in the format of

    0xE0 <command id byte> <p1 byte> <p2 byte> <sizeof buffer> <buffer>

Response buffers are usually in the form of

    <return value byte> <buffer> <0x90> <0x00>

returnValues.h lists all the return statuses

## Compilation

To compile call

    make

To compile and upload to the ledger device

    make load

### Stack Overflow Canary

To get the amount of memory used in the app call the following command

    readelf -s bin/app.elf | grep app_stack_canary 

This will output the canary (which is at the end of the memory space) location then subtract `0x20001800` (Nano S) or
`0xda7a0000` (Nano X) to get the actual used up space for the app.
The NanoS device has 4k of memory for the app and stack.

The app uses the SDK's built in app_stack_canary, it's activated in the makefile by the define `HAVE_BOLOS_APP_STACK_CANARY`
We advise to keep this flag always on, it just gives extra security and doesn't take up much CPU.
The way this works is it defines an int at the end of the stack, initializes it at startup and then check's against it every call to io_exchange, if it changes it throws an `EXCEPTION_IO_RESET`, which should reset the app.
In order to debug a stack overflow, call check_canary() add different parts of the code to check if you have overflowed the stack.

### Error Handling

Errors are propagated through the call stack and it's the command handler's or button handler's job to respond accordingly,
clear the state if they manage it, and return the error back to the caller.

All return values for functions should be checked in every function.

## Key Derivation Algorithm

Ardor signatures are based on a custom variant of the EC-KCDSA over Curve25519 algorithm which is not supported natively by Ledger.

To support standard BIP32 key derivation we implemented curve conversion for Ardor using the protocol [Yaffe-Bender HD key derivation for EC-KCDSA](https://www.jelurida.com/sites/default/files/kcdsa.pdf), it's a derivation scheme that rides on top of the BIP32-Ed25519 HD key derivation scheme.

Technically a public key is a Point (X,Y) on a curve C. X,Y are integers modulo some field F with a base point on the curve G.
The tuple (C, F, G) defines a "curve", in this paper we are dealing with the twisted edwards curve (ed25519) and curve25519.

We are using a morph function between ed25519 and curve25519 so that if `Apoint = Knumber * BasePointED25519` on ed25519 then `morph(Apoint) = Knumber * BasePointECKCDSA` on curve25119
Implementation for this function can be found in curveConversion.c

ed25519 public key is defined as `PublicKeyED25519Point = CLAMP(SHA512(privateKey)[:32]) * ED25519BasePoint`

Let's refer to `CLAMP(SHA512(privateKey)[:32])` as KL

The derivation composition flow for path P is:

1. os_derive_bip32_no_throw derives KLKR and chaincode for P using SLIP10 initialization on 512 bits master seed from bip39/bip32 24 words
2. Derive PublicKeyED25519 using cx_eddsa_get_public_key and KL, the point is encoded as 65 bytes 0x04 XBigEndian YBigEndian
3. PubleyKeyED25519YLE = convert(YBigEndian) - just reverse the bytes
4. PublicKeyCurve25519X = morph(PublicKeyEED25519YLE)

Points on Curve25519 can be defined by the X coordinate (since each X coordinate has only one matching Y coordinate) so PublicKeyCurve25519X and KL should hold `PublicKeyCurve25519X = KL * Curve25519BasePoint = Morphe(KL * ED25519BasePoint)`

In EC-KCDSA publickey = privatekey^-1 * BasePoint, privateKey^-1 is referred to as the key seed, so KL is the key seed for the PublicKeyCurve25519X public key for path P.

Extra Notes:

* ED25519 public keys are compressed into a Y point in little endian encoding having the MSB bit encode the parity of X (since each Y coordinate has two possible X values, X and -X in a prime field F which means if one is even the second is odd)

* In order to derive public keys outside of the ledger (Master public key derivation), all we need is the ed25519 public key and chaincode, described in the derivation scheme.

* Reference code for the derivation implementation can found in the [Ardor source code](https://bitbucket.org/Jelurida/ardor/src/master/)

* [This repo](https://github.com/LedgerHQ/orakolo) implements SLIP10 master seed generation and BIP32 HD EdDSA key derivation in python for reference, [this clone](https://github.com/haimbender/orakolo) also implements master public key derivation for BIP32 EdDSA

* Signing is using the formula `s * (x - h) mod order25519`. This differs from a standard
implementation of EC-KCDSA (`s * (x - h ⊕ r)`). In this custom variant, `h` is calculated as
`H(m || r)` , where `r = [k]G and k = H(m || sk)`.
