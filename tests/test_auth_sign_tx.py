from constants import RESPONSE_SUFFIX, R_SUCCESS, ROOT_SCREENSHOT_PATH, PATH_STR_0, PATH_STR_1
from ragger.navigator import NavInsID
from ardor_command_sender import ArdorCommandSender
from utils import enable_blind_signing

RET_VAL_TRANSACTION_ACCEPTED = 8 # R_FINISHED
RET_VAL_TRANSACTION_REJECTED = 1 # R_REJECT

#
# HOW TO ADD A NEW TEST
#
# To get the unsigned bytes of a transaction, you can use the Ardor wallet API.
# Send the transaction to the wallet API, and then use the "getTransactionBytes" API call.

def _sign_tx_test(backend, navigator, unsigned_bytes_hex: str, expected_signature: str, test_name: str, instructions, signing_account = PATH_STR_0):
    tx_bytes = bytes.fromhex(unsigned_bytes_hex)
    client = ArdorCommandSender(backend)
    with client.load_tx(tx_bytes):
        navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name, instructions)

    rapdu = client.get_async_response()
    assert rapdu is not None
    assert rapdu.status == RESPONSE_SUFFIX
    assert len(rapdu.data) == 2
    assert rapdu.data[0] == R_SUCCESS
    assert rapdu.data[1] == RET_VAL_TRANSACTION_ACCEPTED

    signature = client.sign_tx(signing_account)
    assert signature.hex() == expected_signature

def _sign_tx_reject(backend, navigator, unsigned_bytes_hex: str, test_name: str, instructions):
    tx_bytes = bytes.fromhex(unsigned_bytes_hex)
    client = ArdorCommandSender(backend)
    with client.load_tx(tx_bytes):
        navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name, instructions)

    rapdu = client.get_async_response()
    assert rapdu is not None
    assert rapdu.status == RESPONSE_SUFFIX
    assert len(rapdu.data) == 2
    assert rapdu.data[0] == R_SUCCESS
    assert rapdu.data[1] == RET_VAL_TRANSACTION_REJECTED

    client.sign_tx_reject(PATH_STR_0)

def get_nano_instructions(firmware, nanos_screens: int, nanoxsp_screens: int):
    if firmware.device == 'nanos':
        return [NavInsID.RIGHT_CLICK] * nanos_screens + [NavInsID.BOTH_CLICK]
    elif firmware.device == 'nanox' or firmware.device == 'nanosp':
        return [NavInsID.RIGHT_CLICK] * nanoxsp_screens + [NavInsID.BOTH_CLICK]
    else:
        assert False

def get_stax_instructions(num_taps: int):
    return [NavInsID.USE_CASE_REVIEW_TAP] * num_taps + [NavInsID.USE_CASE_REVIEW_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS]

def test_send_ignis_tx(backend, navigator, firmware):   
    tx_bytes = "020000000000011d98fe090f006e0983e578fab84ab29c209182a8eff30a186fa84211da55a6a29fcc2b7e4a20eb6d36651b82d0eb00c2eb0b0000000000e1f505000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000191ee15a5fb74d1200000000000000000000000000000000000000000000000000000000000000000000000000000000"
    expected_signature = "ad92efeb45e2d0866b22a20ad3bbc75b3fbcd63a32b451665857815598d13800404feca2d6f33730fae127ce89a2213e06afb9e8dbb44e06c7514cb56475e642"
    if firmware.device == 'stax':
        instructions = get_stax_instructions(3)
    else:
        instructions = get_nano_instructions(firmware, 7, 5)
    _sign_tx_test(backend, navigator, tx_bytes, expected_signature, "test_send_ignis_tx", instructions)

def test_send_ignis_tx_reject(backend, navigator, firmware):
    tx_bytes = "020000000000011d98fe090f006e0983e578fab84ab29c209182a8eff30a186fa84211da55a6a29fcc2b7e4a20eb6d36651b82d0eb00c2eb0b0000000000e1f505000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000191ee15a5fb74d1200000000000000000000000000000000000000000000000000000000000000000000000000000000"
    if firmware.device == 'stax':
        instructions = [NavInsID.USE_CASE_REVIEW_TAP] * 3 + [NavInsID.USE_CASE_REVIEW_REJECT, NavInsID.USE_CASE_CHOICE_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS]
    else:
        instructions = get_nano_instructions(firmware, 8, 6)
    _sign_tx_reject(backend, navigator, tx_bytes, "test_send_ignis_tx_reject", instructions)

def test_send_ardr(backend, navigator, firmware):
    tx_bytes = "01000000fe0001f944910a0f00a45834eef72000e08093cb1e23d9c873a9acea0a893bb02738bf8328ba1d076533ece497d15c7f343090b7000000000000e1f5050000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0149e00d5eabea116ebc95800000000"
    expected_signature = "65ee18432849dc797092287436cfb849f1ddf0f288c79f3cb99cb4dc754bac0c1e7dc2f5b6e1cc6542750954d2a5f0572a7fe721bd0bbf9d60f9336a85818ca4"
    if firmware.device == 'stax':
        instructions = get_stax_instructions(3)
    else:
        instructions = get_nano_instructions(firmware, 7, 5)
    _sign_tx_test(backend, navigator, tx_bytes, expected_signature, "test_send_ardr", instructions, PATH_STR_1)

def test_send_ignis_blind_accept(backend, navigator, firmware):
    tx_bytes = "02000000000001887b9a0a0f00a45834eef72000e08093cb1e23d9c873a9acea0a893bb02738bf8328ba1d0765d33f5982ba1e78e080bf76080000000080f0fa020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0149e00d5eabea116ebc958080000000100d66f3134953b76b64b9ceae03fd2a2d858c7b73b7a50eeb901fb489ec387442c000000000000000000000000000000000000000000000000000000000000000000000000"
    expected_signature = "c7c184571ab5515a20d2cff3d25ce58968ca37e6c63ef1b9817f9a7a4caca403071b9e7493aaea299a692d230efa5f367976d886f9c48e1abd091fd148b095c3"
    if firmware.device == 'stax':
        instructions = [NavInsID.USE_CASE_CHOICE_CONFIRM, # confirm enable blind signing
                        NavInsID.USE_CASE_STATUS_DISMISS, # dismiss confirmation screen
                        NavInsID.USE_CASE_REVIEW_TAP,     # ack blind signing operation
                        NavInsID.USE_CASE_REVIEW_TAP,     # ack tx signing operation
                        NavInsID.USE_CASE_REVIEW_TAP,     # chain, amount, recipient
                        NavInsID.USE_CASE_REVIEW_TAP,     # fees
                        NavInsID.USE_CASE_REVIEW_CONFIRM, # confirm tx signing operation
                        NavInsID.USE_CASE_STATUS_DISMISS] # dismiss confirmation screen
    else:
        enable_blind_signing(navigator)
        instructions = get_nano_instructions(firmware, 9, 7)
    _sign_tx_test(backend, navigator, tx_bytes, expected_signature, "test_send_ignis_blind_accept", 
                  instructions, PATH_STR_1)

def test_send_ignis_blind_reject(backend, navigator, firmware):
    tx_bytes = "02000000000001887b9a0a0f00a45834eef72000e08093cb1e23d9c873a9acea0a893bb02738bf8328ba1d0765d33f5982ba1e78e080bf76080000000080f0fa020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0149e00d5eabea116ebc958080000000100d66f3134953b76b64b9ceae03fd2a2d858c7b73b7a50eeb901fb489ec387442c000000000000000000000000000000000000000000000000000000000000000000000000"
    if firmware.device == 'stax':
        instructions = [NavInsID.USE_CASE_CHOICE_REJECT,  # reject blind signing
                        NavInsID.USE_CASE_CHOICE_CONFIRM, # confirm operation rejection
                        NavInsID.USE_CASE_STATUS_DISMISS] # dismiss confirmation screen
    elif firmware.device == 'nanos':
        instructions = [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK]
    else:
        instructions = [NavInsID.BOTH_CLICK]
    _sign_tx_reject(backend, navigator, tx_bytes, "test_send_ignis_blind_reject", instructions)

def test_send_ignis_blind_reject_tx(backend, navigator, firmware):
    tx_bytes = "02000000000001887b9a0a0f00a45834eef72000e08093cb1e23d9c873a9acea0a893bb02738bf8328ba1d0765d33f5982ba1e78e080bf76080000000080f0fa020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0149e00d5eabea116ebc958080000000100d66f3134953b76b64b9ceae03fd2a2d858c7b73b7a50eeb901fb489ec387442c000000000000000000000000000000000000000000000000000000000000000000000000"
    if firmware.device == 'stax':
        instructions = [NavInsID.USE_CASE_CHOICE_CONFIRM, # confirm enable blind signing
                        NavInsID.USE_CASE_STATUS_DISMISS, # dismiss confirmation screen
                        NavInsID.USE_CASE_REVIEW_TAP,     # ack blind signing operation
                        NavInsID.USE_CASE_REVIEW_TAP,     # ack tx signing operation
                        NavInsID.USE_CASE_REVIEW_TAP,     # chain, amount, recipient
                        NavInsID.USE_CASE_REVIEW_TAP,     # fees
                        NavInsID.USE_CASE_REVIEW_REJECT,  # reject tx signing operation
                        NavInsID.USE_CASE_CHOICE_CONFIRM, # ack rejection
                        NavInsID.USE_CASE_STATUS_DISMISS] # dismiss confirmation screen
    else:
        enable_blind_signing(navigator)
        instructions = get_nano_instructions(firmware, 10, 8)
    _sign_tx_reject(backend, navigator, tx_bytes, "test_send_ignis_blind_reject_tx", instructions)

def test_ardor_coin_exchange(backend, navigator, firmware):
    tx_bytes = "01000000fc0001ca81050a0f006e0983e578fab84ab29c209182a8eff30a186fa84211da55a6a29fcc2b7e4a200000000000000000000000000000000080f0fa02000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000191ee15a5fb74d12000000000101000000020000000084d7170000000080f0fa0200000000"
    expected_signature = "c21135e4b982ff3af00185cab80f9aba1c5eaba8d2d9867e841123d3c2c17c0bb2bc3bc769e6714844751c105be64622f94efec668ca41d09b1524e3ee421747"
    if firmware.device == 'stax':
        instructions = get_stax_instructions(2)
    else:
        instructions = get_nano_instructions(firmware, 6, 5)
    _sign_tx_test(backend, navigator, tx_bytes, expected_signature, "test_ardor_coin_exchange", instructions)

def test_coin_exchange(backend, navigator, firmware):
    tx_bytes = "020000000b0001a089050a0f006e0983e578fab84ab29c209182a8eff30a186fa84211da55a6a29fcc2b7e4a200000000000000000000000000000000000e1f505000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000191ee15a5fb74d120000000001020000000400000000c2eb0b0000000080d1f00800000000000000000000000000000000000000000000000000000000000000000000000000000000"
    expected_signature = "26d36905267146675fc76c4ccac52242d0b8afc60007485386448f2bd1031c04f9819069ce6331248a55745643a2f2e4211d08cba0d50ba2de0284bca6125541"
    if firmware.device == 'stax':
        instructions = get_stax_instructions(2)
    else:
        instructions = get_nano_instructions(firmware, 6, 5)
    _sign_tx_test(backend, navigator, tx_bytes, expected_signature, "test_coin_exchange", instructions)

def test_asset_transfer(backend, navigator, firmware):
    tx_bytes = "02000000020101ee8e050a0f006e0983e578fab84ab29c209182a8eff30a186fa84211da55a6a29fcc2b7e4a20eb6d36651b82d0eb000000000000000000e1f505000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000191ee15a5fb74d1200000000013ba0719534c294dcd007000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    expected_signature = "76aaddf7af7fc01f5dc925b3755e7c46072b13ce9a7d46c232711aaa932c6306b437fa833bee1535a0dadb34a8d1f6b5e2131a39086d4ccb80e5eceb028624e0"
    if firmware.device == 'stax':
        instructions = get_stax_instructions(3)
    else:
        instructions = get_nano_instructions(firmware, 9, 6)
    _sign_tx_test(backend, navigator, tx_bytes, expected_signature, "test_asset_transfer", instructions)

def test_send_ignis_4_attachments(backend, navigator, firmware):
    tx_bytes = "020000000000018b07ef0a0f006e0983e578fab84ab29c209182a8eff30a186fa84211da55a6a29fcc2b7e4a20627a6c6937f5eaca00b108190000000000f8590d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0149e00d5eabea116ebc9586c0000000103300089e13a97c49b577a2e602d6ee422eebb37426af6f636fea77ef9968d0b6d890ef6744230f7c030975dc2b45cbdef080c8915cea2345e8cf14822ce90f6c994fe83e0ed79c1f7c0c88f5c694fac0e9d8d0100e7c3eb4eab23682b7e07aa780f63fe3986b326013c49c978cdc4e2b5d8b4e06301e288f39fdad8a465c30c8d9839e707718f4fde871c265cca5b6fea5938a4f91e012b2dd800000100000000000000000000000000000002d33f5982ba1e78e033ece497d15c7f34000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    expected_signature = "3552aaa5cdbf592f21eeee08480c06bb4f634f2b65f9947118623ea2c871bf074316566b2b7a27d8ed3e9f1b61aa6143ff4a2dbe3d16518d9056f0a97a64c053"
    if firmware.device == 'stax':
        instructions = [NavInsID.USE_CASE_CHOICE_CONFIRM, # confirm enable blind signing
                        NavInsID.USE_CASE_STATUS_DISMISS, # dismiss confirmation screen
                        NavInsID.USE_CASE_REVIEW_TAP,     # ack blind signing operation
                        NavInsID.USE_CASE_REVIEW_TAP,     # ack tx signing operation
                        NavInsID.USE_CASE_REVIEW_TAP,     # chain, amount, recipient
                        NavInsID.USE_CASE_REVIEW_TAP,     # fees
                        NavInsID.USE_CASE_REVIEW_CONFIRM, # confirm tx signing operation
                        NavInsID.USE_CASE_STATUS_DISMISS] # dismiss confirmation screen
    else:
        enable_blind_signing(navigator)
        instructions = get_nano_instructions(firmware, 12, 8)
    _sign_tx_test(backend, navigator, tx_bytes, expected_signature, "test_send_ignis_4_attachments", 
                  instructions, PATH_STR_0)

def test_send_ignis_referenced_tx(backend, navigator, firmware):
    tx_bytes = "020000000000018d82f50a0f006e0983e578fab84ab29c209182a8eff30a186fa84211da55a6a29fcc2b7e4a20d33f5982ba1e78e000e1f50500000000a0bb0d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0149e00d5eabea116ebc95800000000020000008ab143bb8f366c938034bfeda9504625a0e5196eed5f2f19ef7388b2c28b0970"
    expected_signature = "150f88bcb590b76a181bd8a0b02551e47a6c6b48445270ad1717353c87bafb07e5058a49212d0c66c89766f089e7af1fa6a4f6d66704ffccd65eeb1bac135fd0"
    if firmware.device == 'stax':
        instructions = [NavInsID.USE_CASE_CHOICE_CONFIRM, # confirm enable blind signing
                        NavInsID.USE_CASE_STATUS_DISMISS, # dismiss confirmation screen
                        NavInsID.USE_CASE_REVIEW_TAP,     # ack blind signing operation
                        NavInsID.USE_CASE_REVIEW_TAP,     # ack tx signing operation
                        NavInsID.USE_CASE_REVIEW_TAP,     # chain, amount, recipient
                        NavInsID.USE_CASE_REVIEW_TAP,     # fees
                        NavInsID.USE_CASE_REVIEW_CONFIRM, # confirm tx signing operation
                        NavInsID.USE_CASE_STATUS_DISMISS] # dismiss confirmation screen
    else:
        enable_blind_signing(navigator)
        instructions = get_nano_instructions(firmware, 8, 6)
    _sign_tx_test(backend, navigator, tx_bytes, expected_signature, "test_send_ignis_referenced_tx", 
                  instructions, PATH_STR_0)

def test_place_asset_exchange_order(backend, navigator, firmware):
    tx_bytes = "02000000020201169bf50a0f006e0983e578fab84ab29c209182a8eff30a186fa84211da55a6a29fcc2b7e4a200000000000000000000000000000000080841e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0149e00d5eabea116ebc9580000000001813b83eafc58a13a030000000000000080de800200000000000000000000000000000000000000000000000000000000000000000000000000000000"
    expected_signature = "2d0fcf25e6afb2015bde4f0d90d75cfeb718dbd80ef35d1adfca95d0b5e69c030349eb41a877bb0ca005ef2e67221d4592b3bc87c22cd3ee35c9c7092eed5055"
    if firmware.device == 'stax':
        instructions = get_stax_instructions(3)
    else:
        enable_blind_signing(navigator)
        instructions = get_nano_instructions(firmware, 8, 6)
    _sign_tx_test(backend, navigator, tx_bytes, expected_signature, "test_place_asset_exchange_order", 
                  instructions, PATH_STR_0)