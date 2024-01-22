#ifdef HAVE_NBGL

#include "display.h"
#include "nbgl_use_case.h"
#include "ardor.h"
#include "glyphs.h"
#include "menu.h"
#include "glyph_symbols.h"
#include "blind_sign_nbgl.h"

static void signTxConfirmation() {
    signTransactionConfirm();
    nbgl_useCaseStatus("TRANSACTION\nSIGNED", true, ui_menu_main);
}

static void signTxCancellation() {
    signTransactionCancel();
    nbgl_useCaseStatus("Transaction\nrejected", false, ui_menu_main);
}

static void askTransactionRejectionConfirmation(void) {
    // display a choice to confirm/cancel rejection
    nbgl_useCaseConfirm("Reject transaction?",
                        NULL,
                        "Yes, Reject",
                        "Go back to transaction",
                        signTxCancellation);
}

// called when long press button on 3rd page is long-touched or when reject footer is touched
static void reviewChoice(bool confirm) {
    if (confirm) {
        signTxConfirmation();
    } else {
        askTransactionRejectionConfirmation();
    }
}

static nbgl_layoutTagValue_t pairs[6];
static nbgl_layoutTagValueList_t pairList;

static void reviewContinue() {
    int i = 0;
    pairs[i].item = "Chain&TxnType";
    pairs[i++].value = state.txnAuth.chainAndTxnTypeText;
    for (int j = 0; j < MAX_WINDOWS; j++) {
        if (*state.txnAuth.windowTitles[j] != 0) {
            pairs[i].item = state.txnAuth.windowTitles[j];
            pairs[i++].value = state.txnAuth.windowTexts[j];
        }
    }
    if (*state.txnAuth.appendagesText != 0) {
        pairs[i].item = "Appendages";
        pairs[i++].value = state.txnAuth.appendagesText;
    }
    pairs[i].item = "Fees";
    pairs[i++].value = state.txnAuth.feeText;

    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = i;
    pairList.pairs = pairs;

    nbgl_pageInfoLongPress_t infoLongPress = {.icon = &C_ArdorIcon64px,
                                              .text = "Sign transaction?",
                                              .longPressText = "Hold to sign"};
    PRINTF("nbgl_useCaseStaticReview\n");
    nbgl_useCaseStaticReview(&pairList, &infoLongPress, "Reject transaction", reviewChoice);
}

void signTransactionScreen() {
    nbgl_useCaseReview_t useCaseReview =
        state.txnAuth.requiresBlindSigning ? nbgl_useCaseReviewBlindSign : nbgl_useCaseReviewStart;
    useCaseReview(&C_ArdorIcon64px,
                  "Review transaction",
                  NULL,
                  "Reject transaction",
                  reviewContinue,
                  askTransactionRejectionConfirmation);
}

#endif