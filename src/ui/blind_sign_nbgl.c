#ifdef HAVE_NBGL

#include "ardor.h"
#include "glyph_symbols.h"
#include "settings.h"

#include "nbgl_use_case.h"

struct use_case_review_ctx_s {
    const nbgl_icon_details_t *icon;
    const char *review_title;
    const char *review_sub_title;
    const char *reject_text;
    nbgl_callback_t continue_callback;
    nbgl_callback_t reject_callback;
};

static struct use_case_review_ctx_s blind_sign_ctx;

static void blind_sign_continue() {
    nbgl_useCaseReviewStart(blind_sign_ctx.icon,
                            blind_sign_ctx.review_title,
                            blind_sign_ctx.review_sub_title,
                            blind_sign_ctx.reject_text,
                            blind_sign_ctx.continue_callback,
                            blind_sign_ctx.reject_callback);
}

static void blind_sign_info() {
    nbgl_useCaseReviewStart(&C_round_warning_64px,
                            "Blind Signing",
                            "This operation cannot be\nsecurely interpreted by\nLedger Stax. It "
                            "might put your\nassets at risk.",
                            blind_sign_ctx.reject_text,
                            blind_sign_continue,
                            blind_sign_ctx.reject_callback);
}

static void blind_sign_choice(bool enable) {
    if (enable) {
        settings_set_allow_blind_signing(true);
        nbgl_useCaseStatus("BLIND SIGNING\nENABLED", true, blind_sign_info);
    } else {
        blind_sign_ctx.reject_callback();
    }
}

void nbgl_useCaseReviewBlindSign(const nbgl_icon_details_t *icon,
                                 const char *review_title,
                                 const char *review_sub_title,
                                 const char *reject_text,
                                 nbgl_callback_t continue_callback,
                                 nbgl_callback_t reject_callback) {
    blind_sign_ctx.icon = icon;
    blind_sign_ctx.review_title = review_title;
    blind_sign_ctx.review_sub_title = review_sub_title;
    blind_sign_ctx.reject_text = reject_text;
    blind_sign_ctx.continue_callback = continue_callback;
    blind_sign_ctx.reject_callback = reject_callback;
    if (N_storage.settings.allowBlindSigning) {
        blind_sign_info();
    } else {
        nbgl_useCaseChoice(&C_round_warning_64px,
                           "Enable blind signing to\nauthorize this\noperation",
                           NULL,
                           "Enable blind signing",
                           reject_text,
                           blind_sign_choice);
    }
}

#endif