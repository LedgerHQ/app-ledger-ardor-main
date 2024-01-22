#ifdef HAVE_BAGL

#include <stdio.h>

#include "ux.h"
#include "display.h"
#include "reedSolomon.h"

char screenContent[27];

UX_STEP_CB(saFlowPage1,
           bnnn_paging,
           showAddressConfirm(),
           {
               .title = "Your Address",
               .text = screenContent,
           });
UX_STEP_CB(saFlowPage2, pb, showAddressConfirm(), {&C_icon_validate_14, "Done"});
UX_FLOW(saFlow, &saFlowPage1, &saFlowPage2);

void showAddressScreen(const uint64_t accountId) {
    explicit_bzero(screenContent, sizeof(screenContent));
    snprintf(screenContent, sizeof(screenContent), APP_PREFIX);
    reedSolomonEncode(accountId, screenContent + strlen(screenContent));

    if (0 == G_ux.stack_count) {
        ux_stack_push();
    }

    ux_flow_init(0, saFlow, NULL);
}

#endif