#include <stdio.h>
#include <string.h>
#include "sha256.h"

uint8_t hex_char_to_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

void hex_to_bytes(const char *hash_input, uint8_t *byte_data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        byte_data[i] = (uint8_t)((hex_char_to_value(hash_input[2 * i]) << 4) | hex_char_to_value(hash_input[2 * i + 1]));
    }
}

void reverse_to_hex(const unsigned char *input, size_t len, unsigned char *output) {
    static const char hex_digits[] = "0123456789abcdef";
    char hex[64];
    
    for (size_t i = 0; i < 32; i++) {
        // Reverse the bytes and convert to hex in one go
        unsigned char byte = input[31 - i];
        output[i] = byte;
        hex[2 * i]     = hex_digits[byte >> 4];
        hex[2 * i + 1] = hex_digits[byte & 0x0F]; 
    }
    
    hex[64] = '\0';
}

void sha256d(unsigned char *byte_data, size_t len, unsigned char *hash, unsigned char *final, char *result) {
    sha256(byte_data, len, hash);
    sha256(hash, 32, final);

}

int main() {
    const char hexstring[] = "000000381f18dc03ee7277be6eb0a5c01724274eb9949a7fdb4202000000000000000000ccca2d81a253bd849f2a16d154a4a21bebe48bcb5c56a7671c414af71f78e0f21d306e67fa970217ceaf3eb3";
    size_t len = 80;
    uint8_t byte_data[len];
    unsigned char hash[32];
    unsigned char final[32];
    unsigned char result[32];

    hex_to_bytes(hexstring, byte_data, len);

    sha256d(byte_data, len, hash, final, result);

    reverse_to_hex(final, 32, result);

    for (int i = 0; i < sizeof(result); i++) {
        printf("%02x", result[i]);
    }
    printf("\n");

}
