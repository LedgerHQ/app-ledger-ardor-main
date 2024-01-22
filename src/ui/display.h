#pragma once

#include <stdint.h>  // uint64_t

///////// show address UI //////////

void showAddressScreen(const uint64_t accountId);

// callback for when the user accepts the address
void showAddressConfirm(void);

// callback for when the user cancels the address display
void showAddressCancel(void);

///////// sign token UI //////////

void signTokenScreen();

// callback for when the user signs the token
void signTokenConfirm(void);

// callback for when the user cancels the token signing
void signTokenCancel(void);

///////// sign transaction UI //////////

void signTransactionScreen();

// callback for when the user signs the transaction
void signTransactionConfirm(void);

// callback for when the user cancels the transaction signing
void signTransactionCancel(void);