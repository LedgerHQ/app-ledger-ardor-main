#ifdef HAVE_BAGL

#include "ux.h"
#include "display.h"
#include "menu.h"
#include "ardor.h"
#include "blind_sign_bagl.h"

static void signTokenConfirmation() {
    signTokenConfirm();
    ui_menu_main();
}

static void signTokenCancellation() {
    signTokenCancel();
    ui_menu_main();
}

UX_STEP_NOCB(stBlindSignWarning,
             pnn,
             {
                 &C_icon_warning,
                 "Blind",
                 "Signing",
             });
UX_STEP_CB(stFlowPage1,
           pb,
           signTokenConfirmation(),
           {
               &C_icon_validate_14,
               "Sign token",
           });
UX_STEP_CB(stFlowPage2,
           pb,
           signTokenCancellation(),
           {
               &C_icon_crossmark,
               "Reject",
           });
UX_FLOW(stFlow, &stBlindSignWarning, &stFlowPage1, &stFlowPage2);

void signTokenScreen() {
    if (N_storage.settings.allowBlindSigning) {
        ux_flow_init(0, stFlow, NULL);
    } else {
        blindSigningNotEnabledScreen(signTokenCancellation);
    }
}

#endif