#ifdef HAVE_BAGL

#include "ux.h"
#include "display.h"
#include "menu.h"
#include "ardor.h"
#include "blind_sign_bagl.h"

static void signTxConfirmation() {
    signTransactionConfirm();
    ui_menu_main();
}

static void signTxCancellation() {
    signTransactionCancel();
    ui_menu_main();
}

#define MAX_NUM_STEPS 10

const ux_flow_step_t *ux_tx_flow[MAX_NUM_STEPS + 1];

UX_STEP_NOCB(ux_tx_initial,
             pnn,
             {
                 &C_icon_eye,
                 "Authorize",
                 "transaction",
             });
UX_STEP_NOCB(ux_tx_blind_signing_warning,
             pnn,
             {
                 &C_icon_warning,
                 "Blind",
                 "Signing",
             });
UX_STEP_NOCB(ux_tx_chain,
             bnnn_paging,
             {
                 .title = "Chain&TxnType",
                 .text = state.txnAuth.chainAndTxnTypeText,
             });
UX_STEP_NOCB(ux_tx_window0,
             bnnn_paging,
             {
                 .title = state.txnAuth.windowTitles[0],
                 .text = state.txnAuth.windowTexts[0],
             });
UX_STEP_NOCB(ux_tx_window1,
             bnnn_paging,
             {
                 .title = state.txnAuth.windowTitles[1],
                 .text = state.txnAuth.windowTexts[1],
             });
UX_STEP_NOCB(ux_tx_window2,
             bnnn_paging,
             {
                 .title = state.txnAuth.windowTitles[2],
                 .text = state.txnAuth.windowTexts[2],
             });
UX_STEP_NOCB(ux_tx_appendages,
             bnnn_paging,
             {
                 .title = "Appendages",
                 .text = state.txnAuth.appendagesText,
             });
UX_STEP_NOCB(ux_tx_fee,
             bnnn_paging,
             {
                 .title = "Fees",
                 .text = state.txnAuth.feeText,
             });
UX_STEP_CB(ux_tx_accept,
           pbb,
           signTxConfirmation(),
           {
               &C_icon_validate_14,
               "Accept",
               "and send",
           });
UX_STEP_CB(ux_tx_reject,
           pb,
           signTxCancellation(),
           {
               &C_icon_crossmark,
               "Reject",
           });

void signTransactionScreen() {
    if (state.txnAuth.requiresBlindSigning && !N_storage.settings.allowBlindSigning) {
        blindSigningNotEnabledScreen(signTxCancellation);
        return;
    }

    uint8_t index = 0;

    ux_tx_flow[index++] = &ux_tx_initial;

    if (state.txnAuth.requiresBlindSigning) {
        ux_tx_flow[index++] = &ux_tx_blind_signing_warning;
    }

    ux_tx_flow[index++] = &ux_tx_chain;

    if (*state.txnAuth.windowTitles[0] != 0) {
        ux_tx_flow[index++] = &ux_tx_window0;
    }

    if (*state.txnAuth.windowTitles[1] != 0) {
        ux_tx_flow[index++] = &ux_tx_window1;
    }

    if (*state.txnAuth.windowTitles[2] != 0) {
        ux_tx_flow[index++] = &ux_tx_window2;
    }

    if (*state.txnAuth.appendagesText != 0) {
        ux_tx_flow[index++] = &ux_tx_appendages;
    }

    ux_tx_flow[index++] = &ux_tx_fee;
    ux_tx_flow[index++] = &ux_tx_accept;
    ux_tx_flow[index++] = &ux_tx_reject;

    ux_tx_flow[index++] = FLOW_END_STEP;
    ux_flow_init(0, ux_tx_flow, NULL);
}

#endif