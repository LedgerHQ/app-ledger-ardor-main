#ifdef HAVE_NBGL

#include <string.h>  // memset

#include "menu.h"
#include "display.h"
#include "glyphs.h"
#include "nbgl_use_case.h"
#include "reedSolomon.h"

static char rsAddress[27];

static void confirm_address_approval(void) {
    nbgl_useCaseStatus("ADDRESS\nVERIFIED", true, showAddressConfirm);
}

static void confirm_address_rejection(void) {
    nbgl_useCaseStatus("Address verification\ncancelled", false, showAddressCancel);
}

static void reviewChoice(bool confirm) {
    if (confirm) {
        confirm_address_approval();
    } else {
        confirm_address_rejection();
    }
}

static void continueReview(void) {
    nbgl_useCaseAddressConfirmation(rsAddress, reviewChoice);
}

void showAddressScreen(const uint64_t accountId) {
    explicit_bzero(rsAddress, sizeof(rsAddress));
    snprintf(rsAddress, sizeof(rsAddress), APP_PREFIX);
    reedSolomonEncode(accountId, rsAddress + strlen(rsAddress));

    nbgl_useCaseReviewStart(&C_ArdorIcon64px,
                            "Verify Ardor address",
                            NULL,
                            "Cancel",
                            continueReview,
                            confirm_address_rejection);
}

#endif