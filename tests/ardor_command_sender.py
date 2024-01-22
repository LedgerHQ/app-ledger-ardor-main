from contextlib import contextmanager
from typing import Generator, List, Optional
from ragger.backend.interface import BackendInterface, RAPDU
from constants import CLA, RESPONSE_SUFFIX, R_SUCCESS, R_TXN_UNAUTHORIZED
from bip_utils import Bip32Utils

INS_AUTH_SIGN_TXN = 0x03
TX_P1_INIT = 0x01
TX_P1_CONTINUE = 0x02
TX_P1_SIGN = 0x03

INS_SHOW_ADDRESS = 0x05

INS_SIGN_TOKEN = 0x07
TK_P1_INIT = 0x00
TK_P1_MSG_BYTES = 0x01
TK_P1_SIGN = 0x02

CHUNK_SIZE = 128
SIGNATURE_LENGTH = 64

def split_message(message: bytes, max_size: int) -> List[bytes]:
    return [message[x:x + max_size] for x in range(0, len(message), max_size)]

def pack_derivation_path(derivation_path: str) -> bytes:
    split = derivation_path.split("/")

    if split[0] != "m":
        raise ValueError("Error master expected")

    path_bytes: bytes = b''
    for value in split[1:]:
        if value == "":
            raise ValueError(f'Error missing value in split list "{split}"')
        if value.endswith('\''):
            path_bytes += Bip32Utils.HardenIndex(int(value[:-1])).to_bytes(4, byteorder='little')
        else:
            path_bytes += int(value).to_bytes(4, byteorder='little')
    return path_bytes


class ArdorCommandSender:
    def __init__(self, backend: BackendInterface) -> None:
        self.backend = backend

    @contextmanager
    def load_tx(self, transaction: bytes) -> Generator[None, None, None]:
        messages = split_message(transaction, CHUNK_SIZE)
        self.backend.exchange(cla=CLA,
                              ins=INS_AUTH_SIGN_TXN,
                              p1=((len(transaction) & 0b0011111100000000) >> 6) | TX_P1_INIT,
                              p2=len(transaction) & 0xff,
                              data=messages[0])

        for msg in messages[1:-1]:
            self.backend.exchange(cla=CLA, ins=INS_AUTH_SIGN_TXN, p1=TX_P1_CONTINUE, p2=0, data=msg)

        with self.backend.exchange_async(cla=CLA, ins=INS_AUTH_SIGN_TXN, p1=TX_P1_CONTINUE, p2=0, data=messages[-1]) as response:
            yield response

    def get_async_response(self) -> Optional[RAPDU]:
        return self.backend.last_async_response
    
    def sign_tx(self, path: str) -> RAPDU:
        rapdu = self.backend.exchange(cla=CLA, ins=INS_AUTH_SIGN_TXN, p1=TX_P1_SIGN, data=pack_derivation_path(path))
        assert rapdu is not None
        assert rapdu.status == RESPONSE_SUFFIX
        assert len(rapdu.data) == 1 + SIGNATURE_LENGTH
        assert rapdu.data[0] == R_SUCCESS
        return rapdu.data[1:]
    
    def sign_tx_reject(self, path: str):
        rapdu = self.backend.exchange(cla=CLA, ins=INS_AUTH_SIGN_TXN, p1=TX_P1_SIGN, data=pack_derivation_path(path))
        assert rapdu is not None
        assert rapdu.status == RESPONSE_SUFFIX
        assert len(rapdu.data) == 1
        assert rapdu.data[0] == R_TXN_UNAUTHORIZED

    @contextmanager
    def show_address(self, path: str) -> Generator[None, None, None]:
        with self.backend.exchange_async(cla=CLA, ins=INS_SHOW_ADDRESS, data=pack_derivation_path(path)) as response:
            yield response
    
    def sign_token_init(self) -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=INS_SIGN_TOKEN, p1=TK_P1_INIT)
    
    def sign_token_send_bytes(self, data: bytes) -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=INS_SIGN_TOKEN, p1=TK_P1_MSG_BYTES, data=data)
    
    @contextmanager
    def sign_token_sign(self, path: str, timestamp: int) -> Generator[None, None, None]:
        with self.backend.exchange_async(cla=CLA, ins=INS_SIGN_TOKEN, p1=TK_P1_SIGN, 
                                         data=timestamp.to_bytes(4, byteorder='little') + pack_derivation_path(path)) as response:
            yield response