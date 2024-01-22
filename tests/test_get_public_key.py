from constants import CLA, RESPONSE_SUFFIX, PATH_STR_0, PATH_STR_3, PUBLIC_KEY_0, PUBLIC_KEY_3, R_SUCCESS
from ardor_command_sender import pack_derivation_path

INS_GET_PUBLIC_KEY_AND_CHAIN_CODE = 0x06
P1 = 0x01

def test_get_public_key0(backend):
    rapdu = backend.exchange(cla=CLA, ins=INS_GET_PUBLIC_KEY_AND_CHAIN_CODE, p1=P1, data=pack_derivation_path(PATH_STR_0))
    assert rapdu is not None
    assert rapdu.status == RESPONSE_SUFFIX
    assert len(rapdu.data) == 1 + 32 # 1 byte return value, 32 bytes public key
    assert rapdu.data[0] == R_SUCCESS
    assert rapdu.data[1:].hex() == PUBLIC_KEY_0

def test_get_public_key3(backend):
    rapdu = backend.exchange(cla=CLA, ins=INS_GET_PUBLIC_KEY_AND_CHAIN_CODE, p1=P1, data=pack_derivation_path(PATH_STR_3))
    assert rapdu is not None
    assert rapdu.status == RESPONSE_SUFFIX
    assert len(rapdu.data) == 1 + 32 # 1 byte return value, 32 bytes public key
    assert rapdu.data[0] == R_SUCCESS
    assert rapdu.data[1:].hex() == PUBLIC_KEY_3
