#include "io_helper.h"
#include "io.h"  // io_send_response_pointer

#define SW_OK 0x9000

int io_send_return1(uint8_t ret) {
    return io_send_response_pointer(&(const uint8_t){ret}, 1, SW_OK);
}

int io_send_return2(uint8_t byte1, uint8_t byte2) {
    return io_send_response_pointer((const uint8_t *) &(const uint8_t[2]){byte1, byte2}, 2, SW_OK);
}

int io_send_return3(uint8_t byte1, uint8_t byte2, uint8_t byte3) {
    return io_send_response_pointer((const uint8_t *) &(const uint8_t[3]){byte1, byte2, byte3},
                                    3,
                                    SW_OK);
}