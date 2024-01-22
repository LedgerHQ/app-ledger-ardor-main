#pragma once

#ifdef HAVE_NBGL

#include "nbgl_use_case.h"

typedef void (*nbgl_useCaseReview_t)(const nbgl_icon_details_t *icon,
                                     const char *review_title,
                                     const char *review_sub_title,
                                     const char *reject_text,
                                     nbgl_callback_t continue_callback,
                                     nbgl_callback_t reject_callback);

void nbgl_useCaseReviewBlindSign(const nbgl_icon_details_t *icon,
                                 const char *review_title,
                                 const char *review_sub_title,
                                 const char *reject_text,
                                 nbgl_callback_t continue_callback,
                                 nbgl_callback_t reject_callback);

#endif