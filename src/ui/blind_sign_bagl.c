#ifdef HAVE_BAGL

#include "blind_sign_bagl.h"
#include "ux.h"

callback_void_t bsNotEnabledCallback;

static void blindSigningNotEnabledCallback() {
    bsNotEnabledCallback();
}

#ifdef TARGET_NANOS

UX_STEP_CB(ux_step_blind_signing_not_enabled,
           bnnn_paging,
           blindSigningNotEnabledCallback(),
           {"ERROR", "Blind signing must be enabled on Settings"});
UX_FLOW(ux_flow_blind_signing_not_enabled, &ux_step_blind_signing_not_enabled);

#else

UX_STEP_CB(ux_step_blind_signing_not_enabled,
           pnn,
           blindSigningNotEnabledCallback(),
           {&C_icon_crossmark, "Blind signing must be", "enabled on Settings"});
UX_FLOW(ux_flow_blind_signing_not_enabled, &ux_step_blind_signing_not_enabled);

#endif

void blindSigningNotEnabledScreen(callback_void_t callback) {
    bsNotEnabledCallback = callback;
    ux_flow_init(0, ux_flow_blind_signing_not_enabled, NULL);
}

#endif