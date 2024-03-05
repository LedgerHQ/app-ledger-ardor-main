#ifdef HAVE_NBGL

#include "menu.h"
#include "glyphs.h"
#include "nbgl_use_case.h"
#include "os.h"
#include "ardor.h"
#include "settings.h"

void app_quit(void) {
    // exit app here
    os_sched_exit(-1);
}

///////////////////////////////////////////////////////////////////////////
// Settings menu:

static const char* const INFO_TYPES[] = {"Version", "Developer"};
static const char* const INFO_CONTENTS[] = {APPVERSION, "Jelurida"};

enum {
    BLIND_SIGNING_IDX = 0,
    NB_SETTINGS,
};
static nbgl_layoutSwitch_t G_switches[NB_SETTINGS];

enum {
    BLIND_SIGNING_TOKEN = FIRST_USER_TOKEN,
};

#define SETTINGS_PAGE_NUMBER 2
static bool settings_nav_callback(uint8_t page, nbgl_pageContent_t* content) {
    if (page == 0) {
        content->type = INFOS_LIST;
        content->infosList.nbInfos = ARRAY_COUNT(INFO_TYPES);
        content->infosList.infoTypes = INFO_TYPES;
        content->infosList.infoContents = INFO_CONTENTS;
    } else if (page == 1) {
        // Read again the NVM as the value might have changed following a user touch
        if (N_storage.settings.allowBlindSigning == false) {
            G_switches[BLIND_SIGNING_IDX].initState = OFF_STATE;
        } else {
            G_switches[BLIND_SIGNING_IDX].initState = ON_STATE;
        }
        content->type = SWITCHES_LIST;
        content->switchesList.nbSwitches = NB_SETTINGS;
        content->switchesList.switches = G_switches;
    } else {
        return false;
    }
    return true;
}

static void settings_controls_callback(int token, uint8_t index) {
    UNUSED(index);
    if (token == BLIND_SIGNING_TOKEN) {
        // Write in NVM the opposite of what the current toggle is
        settings_set_allow_blind_signing(G_switches[BLIND_SIGNING_IDX].initState != ON_STATE);
    }
}

static void ui_menu_settings() {
    G_switches[BLIND_SIGNING_IDX].text = "Blind signing";
    G_switches[BLIND_SIGNING_IDX].subText = "Enable blind signing";
    G_switches[BLIND_SIGNING_IDX].token = BLIND_SIGNING_TOKEN;
    G_switches[BLIND_SIGNING_IDX].tuneId = TUNE_TAP_CASUAL;

    nbgl_useCaseSettings(APPNAME " settings",
                         0,
                         SETTINGS_PAGE_NUMBER,
                         false,
                         ui_menu_main,
                         settings_nav_callback,
                         settings_controls_callback);
}

///////////////////////////////////////////////////////////////////////////

void ui_menu_main(void) {
    nbgl_useCaseHome(APPNAME, &C_ArdorIcon64px, NULL, true, ui_menu_settings, app_quit);
}

#endif