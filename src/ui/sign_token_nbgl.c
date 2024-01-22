#ifdef HAVE_NBGL

#include "display.h"
#include "nbgl_use_case.h"
#include "glyphs.h"
#include "menu.h"
#include "glyph_symbols.h"
#include "blind_sign_nbgl.h"

static void signTokenConfirmation() {
    signTokenConfirm();
    nbgl_useCaseStatus("TOKEN SIGNED", true, ui_menu_main);
}

static void signTokenCancellation() {
    signTokenCancel();
    nbgl_useCaseStatus("Token signature\ncancelled", false, ui_menu_main);
}

static void reviewChoice(bool confirm) {
    if (confirm) {
        signTokenConfirmation();
    } else {
        signTokenCancellation();
    }
}

static void reviewContinue() {
    nbgl_layoutTagValueList_t pairList = {.nbMaxLinesForValue = 0, .nbPairs = 0, .pairs = NULL};

    nbgl_pageInfoLongPress_t infoLongPress = {.icon = &C_ArdorIcon64px,
                                              .text = "Sign token",
                                              .longPressText = "Hold to sign"};

    nbgl_useCaseStaticReview(&pairList, &infoLongPress, "Cancel", reviewChoice);
}

static void askSignatureRejectionConfirmation(void) {
    // display a choice to confirm/cancel rejection
    nbgl_useCaseConfirm("Reject signature?", NULL, "Yes, Reject", "Go back", signTokenCancellation);
}

void signTokenScreen() {
    nbgl_useCaseReviewBlindSign(&C_ArdorIcon64px,
                                "Token signature",
                                NULL,
                                "Reject",
                                reviewContinue,
                                askSignatureRejectionConfirmation);
}

#endif