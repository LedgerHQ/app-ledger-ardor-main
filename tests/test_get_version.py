from constants import CLA, RESPONSE_SUFFIX

INS_GET_VERSION = 0x01

def test_get_version(backend):
    rapdu = backend.exchange(cla=CLA, ins=INS_GET_VERSION)
    assert rapdu.status == RESPONSE_SUFFIX
    assert rapdu.data.hex() == "01010000babe00"