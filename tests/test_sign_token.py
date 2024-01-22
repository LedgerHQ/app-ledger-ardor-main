from ardor_command_sender import ArdorCommandSender
from constants import PATH_STR_0, R_SUCCESS, RESPONSE_SUFFIX, ROOT_SCREENSHOT_PATH, R_REJECT
from utils import enable_blind_signing

from ragger.navigator import NavInsID

def _send_token_for_signing(backend) -> ArdorCommandSender:
    msg = "Token Data"

    client = ArdorCommandSender(backend)
    rapdu = client.sign_token_init()
    assert rapdu is not None
    assert rapdu.status == RESPONSE_SUFFIX
    assert len(rapdu.data) == 1
    assert rapdu.data[0] == R_SUCCESS
    
    rapdu = client.sign_token_send_bytes(msg.encode())
    assert rapdu is not None
    assert rapdu.status == RESPONSE_SUFFIX
    assert len(rapdu.data) == 1
    assert rapdu.data[0] == R_SUCCESS
    return client

def test_sign_token(backend, navigator, firmware):
    timestamp = 167772040
    expected_token = "6e0983e578fab84ab29c209182a8eff30a186fa84211da55a6a29fcc2b7e4a2088ffff094b85d2d6ba9b42993f8d1cf585cd64d09be0632e1f303e3142a4421296683f055a1f816e7e414bf51389416659ff6ff32beee4b08d5d1ce299f43a448f6b9fb0"

    client = _send_token_for_signing(backend)

    if firmware.device == 'stax':
        instructions = [NavInsID.USE_CASE_CHOICE_CONFIRM, # confirm enable blind signing
                        NavInsID.USE_CASE_STATUS_DISMISS, # dismiss confirmation screen
                        NavInsID.USE_CASE_REVIEW_TAP,     # ack blind signing operation
                        NavInsID.USE_CASE_REVIEW_TAP,     # ack token signing operation
                        NavInsID.USE_CASE_REVIEW_CONFIRM, # confirm token signing operation
                        NavInsID.USE_CASE_STATUS_DISMISS] # dismiss confirmation screen
    else:
        enable_blind_signing(navigator)
        instructions = [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK]
    
    with client.sign_token_sign(PATH_STR_0, timestamp):
        navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, "test_sign_token", instructions)
    
    rapdu = client.get_async_response()
    assert rapdu is not None
    assert rapdu.status == RESPONSE_SUFFIX
    assert len(rapdu.data) == 1 + 100
    assert rapdu.data[0] == R_SUCCESS
    assert rapdu.data[1:].hex() == expected_token

def test_sign_token_reject_blind(backend, navigator, firmware):
    timestamp = 167772040

    client = _send_token_for_signing(backend)

    if firmware.device == 'stax':
        instructions = [NavInsID.USE_CASE_CHOICE_REJECT,  # reject blind signing
                        NavInsID.USE_CASE_CHOICE_CONFIRM, # confirm operation rejection
                        NavInsID.USE_CASE_STATUS_DISMISS] # dismiss confirmation screen
    elif firmware.device == 'nanos':
        instructions = [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK]
    else:
        instructions = [NavInsID.BOTH_CLICK]
    
    with client.sign_token_sign(PATH_STR_0, timestamp):
        navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, "test_sign_token_reject_blind", instructions)

    rapdu = client.get_async_response()
    assert rapdu is not None
    assert rapdu.status == RESPONSE_SUFFIX
    assert len(rapdu.data) == 2
    assert rapdu.data[0] == R_SUCCESS
    assert rapdu.data[1] == R_REJECT

def test_sign_token_reject_tx(backend, navigator, firmware):
    timestamp = 167772040

    client = _send_token_for_signing(backend)

    if firmware.device == 'stax':
        instructions = [NavInsID.USE_CASE_CHOICE_CONFIRM, # confirm enable blind signing
                        NavInsID.USE_CASE_STATUS_DISMISS, # dismiss confirmation screen
                        NavInsID.USE_CASE_REVIEW_TAP,     # ack blind signing operation
                        NavInsID.USE_CASE_REVIEW_TAP,     # ack token signing operation
                        NavInsID.USE_CASE_CHOICE_REJECT,  # reject token signing operation
                        NavInsID.USE_CASE_STATUS_DISMISS] # dismiss confirmation screen
    else:
        enable_blind_signing(navigator)
        instructions = [NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK]
    
    with client.sign_token_sign(PATH_STR_0, timestamp):
        navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, "test_sign_token_reject_tx", instructions)

    rapdu = client.get_async_response()
    assert rapdu is not None
    assert rapdu.status == RESPONSE_SUFFIX
    assert len(rapdu.data) == 2
    assert rapdu.data[0] == R_SUCCESS
    assert rapdu.data[1] == R_REJECT