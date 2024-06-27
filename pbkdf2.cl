void hmac_sha512(uchar *key, int key_length, uchar *data, int data_length, uchar *output);

__kernel void pbkdf2_hmac_sha512(__global const uchar *password, __global const uchar *salt, uint iterations, __global uchar *output) {
    int id = get_global_id(0);
    uchar key[64];
    uchar buffer[64];
    uchar temp[64];
    uchar salt_block[64];
    uint i, j, k;

    for (i = 0; i < 32; i++) {
        salt_block[i] = salt[i];
    }

    salt_block[32] = (id >> 24) & 0xFF;
    salt_block[33] = (id >> 16) & 0xFF;
    salt_block[34] = (id >> 8) & 0xFF;
    salt_block[35] = id & 0xFF;

    hmac_sha512(password, 32, salt_block, 36, key);
    for (i = 0; i < 32; i++) {
        buffer[i] = key[i];
    }

    for (i = 1; i < iterations; i++) {
        hmac_sha512(password, 32, buffer, 32, temp);
        for (j = 0; j < 32; j++) {
            key[j] ^= temp[j];
            buffer[j] = temp[j];
        }
    }

    for (k = 0; k < 32; k++) {
        output[id * 32 + k] = key[k];
    }
}
