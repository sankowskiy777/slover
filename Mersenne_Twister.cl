__kernel void mersenne_twister(__global uint *mt, __global uint *entropies, uint seed) {
    int idx = get_global_id(0);
    mt[idx] = seed + idx;
    for (int i = 1; i < 624; i++) {
        mt[i] = 1812433253U * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i;
    }
    for (int i = 0; i < 16; i++) {
        int y = (mt[i] & 0x80000000) + (mt[(i+1) % 624] & 0x7fffffff);
        mt[i] = mt[(i + 397) % 624] ^ (y >> 1);
        if (y % 2 != 0) {
            mt[i] ^= 2567483615U;
        }
        entropies[i] = mt[i];
    }
}
