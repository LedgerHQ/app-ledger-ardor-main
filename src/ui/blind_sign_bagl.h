#pragma once

#ifdef HAVE_BAGL

typedef void (*callback_void_t)(void);

void blindSigningNotEnabledScreen(callback_void_t callback);

#endif