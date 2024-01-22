from ardor_command_sender import ArdorCommandSender
from constants import PATH_STR_0, ROOT_SCREENSHOT_PATH, PATH_STR_3
from ragger.navigator import NavInsID

def show_address_test(backend, navigator, firmware, path, test_name):
    if firmware.device == 'nanos':
        instructions=[NavInsID.RIGHT_CLICK] * 2 + [NavInsID.BOTH_CLICK]
    elif firmware.device == 'nanox' or firmware.device == 'nanosp':
        instructions=[NavInsID.RIGHT_CLICK] * 1 + [NavInsID.BOTH_CLICK]
    elif firmware.device == 'stax':
        instructions=[NavInsID.USE_CASE_ADDRESS_CONFIRMATION_TAP, NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CONFIRM]
    else:
        assert False

    client = ArdorCommandSender(backend)
    with client.show_address(path):
        navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name, instructions)

def test_show_address0(backend, navigator, firmware):
    show_address_test(backend, navigator, firmware, PATH_STR_0, "test_show_address0")

def test_show_address3(backend, navigator, firmware):
    show_address_test(backend, navigator, firmware, PATH_STR_3, "test_show_address3")