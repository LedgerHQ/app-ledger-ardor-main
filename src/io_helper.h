#pragma once

#include <stdint.h>

int io_send_return1(uint8_t ret);
int io_send_return2(uint8_t byte1, uint8_t byte2);
int io_send_return3(uint8_t byte1, uint8_t byte2, uint8_t byte3);