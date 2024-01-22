#include "ardor.h"
#include "stdbool.h"

void settings_set_allow_blind_signing(bool value) {
    nvm_write((void*) &N_storage.settings.allowBlindSigning, &value, sizeof(value));
}