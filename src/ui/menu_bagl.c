#ifdef HAVE_BAGL

#include "ux.h"
#include "menu.h"
#include "glyphs.h"
#include "ardor.h"

//////////////////////////////////////////////////////////////////////
static const char* allow_blind_sign_data_getter(unsigned int idx);
static void allow_blind_sign_data_selector(unsigned int idx);

//////////////////////////////////////////////////////////////////////////////////////
// Settings menu:

enum SettingsMenuOption {
    SettingsMenuOptionAllowBlindSign,
    // back must remain last
    SettingsMenuOptionBack
};

static unsigned int settings_submenu_option_index(enum SettingsMenuOption settings_menu_option) {
    if (settings_menu_option == SettingsMenuOptionAllowBlindSign) {
        return (unsigned int) settings_menu_option;
    } else {
        return 0;
    }
}

const char* const settings_submenu_getter_values[] = {
    "Allow blind signing",
    "Back",
};

static const char* settings_submenu_getter(unsigned int idx) {
    if (idx < ARRAYLEN(settings_submenu_getter_values)) {
        return settings_submenu_getter_values[idx];
    }
    return NULL;
}

static void settings_submenu_selector(unsigned int idx) {
    if (idx == 0) {
        ux_menulist_init_select(0,
                                allow_blind_sign_data_getter,
                                allow_blind_sign_data_selector,
                                N_storage.settings.allowBlindSigning);
    } else {
        ui_menu_main();
    }
}

//////////////////////////////////////////////////////////////////////////////////////
// Allow blind signing submenu

static void allow_blind_sign_data_change(bool blind_sign) {
    nvm_write((void*) &N_storage.settings.allowBlindSigning, &blind_sign, sizeof(blind_sign));
}

const char* const no_yes_data_getter_values[] = {"No", "Yes", "Back"};

static const char* allow_blind_sign_data_getter(unsigned int idx) {
    if (idx < ARRAYLEN(no_yes_data_getter_values)) {
        return no_yes_data_getter_values[idx];
    }
    return NULL;
}

static void allow_blind_sign_data_selector(unsigned int idx) {
    switch (idx) {
        case 0:
            allow_blind_sign_data_change(false);
            break;
        case 1:
            allow_blind_sign_data_change(true);
            break;
        default:
            break;
    }
    unsigned int select_item = settings_submenu_option_index(SettingsMenuOptionAllowBlindSign);
    ux_menulist_init_select(0, settings_submenu_getter, settings_submenu_selector, select_item);
}

//////////////////////////////////////////////////////////////////////

UX_STEP_NOCB(ux_idle_flow_1_step,
             bn,
             {
                 "Application",
                 "is ready",
             });
UX_STEP_CB(ux_idle_flow_2_step,
           pb,
           ux_menulist_init(0, settings_submenu_getter, settings_submenu_selector),
           {
               &C_icon_coggle,
               "Settings",
           });
UX_STEP_NOCB(ux_idle_flow_3_step,
             bn,
             {
                 "Version",
                 APPVERSION,
             });
UX_STEP_CB(ux_idle_flow_4_step,
           pb,
           os_sched_exit(-1),
           {
               &C_icon_dashboard,
               "Quit",
           });
UX_FLOW(ux_idle_flow,
        &ux_idle_flow_1_step,
        &ux_idle_flow_2_step,
        &ux_idle_flow_3_step,
        &ux_idle_flow_4_step);

void ui_menu_main() {
    // reserve a display stack slot if none yet
    if (G_ux.stack_count == 0) {
        ux_stack_push();
    }
    ux_flow_init(0, ux_idle_flow, NULL);
}

#endif