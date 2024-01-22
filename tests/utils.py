from ragger.navigator import NavInsID

def enable_blind_signing(navigator):
    navigator.navigate([NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, NavInsID.BOTH_CLICK,
                        NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, NavInsID.RIGHT_CLICK, 
                        NavInsID.BOTH_CLICK], screen_change_before_first_instruction=False)