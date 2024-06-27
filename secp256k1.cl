#include <stdint.h>
#include <string.h>

typedef unsigned int uint32;

typedef struct {
    uint32 n[8];
} secp256k1_fe;

typedef struct {
    secp256k1_fe x;
    secp256k1_fe y;
    secp256k1_fe z;
    int infinity;
} secp256k1_gej;

typedef struct {
    secp256k1_fe x;
    secp256k1_fe y;
    int infinity;
} secp256k1_ge;

typedef struct {
    uint32 n[8];
} secp256k1_fe_storage;

typedef struct {
    secp256k1_fe_storage x;
    secp256k1_fe_storage y;
} secp256k1_ge_storage;

typedef struct {
    unsigned char data[64];
} secp256k1_pubkey;

typedef struct {
    uint32 d[8];
} secp256k1_scalar;

#define SECP256K1_GE_STORAGE_CONST static const
#define ECMULT_GEN_PREC_N 64
#define ECMULT_GEN_PREC_B 4
#define ECMULT_GEN_PREC_G 16

void secp256k1_ge_clear(secp256k1_ge *r);
void secp256k1_gej_set_infinity(secp256k1_gej *r);
void secp256k1_ge_set_gej(secp256k1_ge *r, const secp256k1_gej *a);
void secp256k1_scalar_clear(secp256k1_scalar *r);
int secp256k1_scalar_is_zero(const secp256k1_scalar *a);
int secp256k1_scalar_set_b32_seckey(secp256k1_scalar *r, const unsigned char *bin);
void secp256k1_scalar_cmov(secp256k1_scalar *r, const secp256k1_scalar *a, int flag);
int secp256k1_scalar_get_bits(const secp256k1_scalar *a, int offset, int count);
void secp256k1_ge_from_storage(secp256k1_ge *r, const secp256k1_ge_storage *a);
void secp256k1_gej_add_ge(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_ge *b);
void secp256k1_fe_normalize_var(secp256k1_fe *r);
void secp256k1_fe_get_b32(unsigned char *r, const secp256k1_fe *a);
void secp256k1_scalar_add(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b);
void secp256k1_fe_set_b32(secp256k1_fe *r, const unsigned char *a);
void secp256k1_ge_set_xy(secp256k1_ge *r, const secp256k1_fe *x, const secp256k1_fe *y);
int secp256k1_ge_is_infinity(const secp256k1_ge *a);
int secp256k1_fe_is_odd(const secp256k1_fe *a);
void secp256k1_fe_inv(secp256k1_fe *r, const secp256k1_fe *a);
void secp256k1_fe_sqr(secp256k1_fe *r, const secp256k1_fe *a);
void secp256k1_fe_mul(secp256k1_fe *r, const secp256k1_fe *a, const secp256k1_fe *b);

__constant secp256k1_ge_storage prec[ECMULT_GEN_PREC_N][ECMULT_GEN_PREC_G] = {
    // заполните этот массив данными
};

static void secp256k1_ecmult_gen(secp256k1_gej *r, secp256k1_scalar *gn) {
    secp256k1_ge add;
    secp256k1_ge_storage adds;
    int bits;
    int i, j;

    memset(&adds, 0, sizeof(adds));
    secp256k1_gej_set_infinity(r);

    add.infinity = 0;
    for (j = 0; j < ECMULT_GEN_PREC_N; j++) {
        bits = secp256k1_scalar_get_bits(gn, j * ECMULT_GEN_PREC_B, ECMULT_GEN_PREC_B);
        for (i = 0; i < ECMULT_GEN_PREC_G; i++) {
            uint32_t mask0, mask1;
            mask0 = (i == bits) + ~((uint32_t)0);
            mask1 = ~mask0;

            adds.x.n[0] = (adds.x.n[0] & mask0) | (prec[j][i].x.n[0] & mask1);
            adds.x.n[1] = (adds.x.n[1] & mask0) | (prec[j][i].x.n[1] & mask1);
            adds.x.n[2] = (adds.x.n[2] & mask0) | (prec[j][i].x.n[2] & mask1);
            adds.x.n[3] = (adds.x.n[3] & mask0) | (prec[j][i].x.n[3] & mask1);
            adds.x.n[4] = (adds.x.n[4] & mask0) | (prec[j][i].x.n[4] & mask1);
            adds.x.n[5] = (adds.x.n[5] & mask0) | (prec[j][i].x.n[5] & mask1);
            adds.x.n[6] = (adds.x.n[6] & mask0) | (prec[j][i].x.n[6] & mask1);
            adds.x.n[7] = (adds.x.n[7] & mask0) | (prec[j][i].x.n[7] & mask1);

            adds.y.n[0] = (adds.y.n[0] & mask0) | (prec[j][i].y.n[0] & mask1);
            adds.y.n[1] = (adds.y.n[1] & mask0) | (prec[j][i].y.n[1] & mask1);
            adds.y.n[2] = (adds.y.n[2] & mask0) | (prec[j][i].y.n[2] & mask1);
            adds.y.n[3] = (adds.y.n[3] & mask0) | (prec[j][i].y.n[3] & mask1);
            adds.y.n[4] = (adds.y.n[4] & mask0) | (prec[j][i].y.n[4] & mask1);
            adds.y.n[5] = (adds.y.n[5] & mask0) | (prec[j][i].y.n[5] & mask1);
            adds.y.n[6] = (adds.y.n[6] & mask0) | (prec[j][i].y.n[6] & mask1);
            adds.y.n[7] = (adds.y.n[7] & mask0) | (prec[j][i].y.n[7] & mask1);
        }
        secp256k1_ge_from_storage(&add, &adds);
        secp256k1_gej_add_ge(r, r, &add);
    }
    bits = 0;
    secp256k1_ge_clear(&add);
}

static void secp256k1_pubkey_save(secp256k1_pubkey* pubkey, secp256k1_ge* ge) {
    secp256k1_fe_normalize_var(&ge->x);
    secp256k1_fe_normalize_var(&ge->y);
    secp256k1_fe_get_b32(pubkey->data, &ge->x);
    secp256k1_fe_get_b32(pubkey->data + 32, &ge->y);
}

int secp256k1_ec_pubkey_create(secp256k1_pubkey *pubkey, const unsigned char *seckey) {
    secp256k1_gej pj;
    secp256k1_ge p;
    secp256k1_scalar sec;
    secp256k1_scalar secp256k1_scalar_one = { .d = {0, 0, 0, 0, 0, 0, 0, 1} };
    int ret = 0;

    memset(pubkey, 0, sizeof(*pubkey));

    ret = secp256k1_scalar_set_b32_seckey(&sec, seckey);

    secp256k1_scalar_cmov(&sec, &secp256k1_scalar_one, !ret);

    secp256k1_ecmult_gen(&pj, &sec);
    secp256k1_ge_set_gej(&p, &pj);
    secp256k1_pubkey_save(pubkey, &p);

    memczero(pubkey, sizeof(*pubkey), !ret);

    secp256k1_scalar_clear(&sec);
    return ret;
}

static int secp256k1_eckey_privkey_tweak_add(secp256k1_scalar *key, const secp256k1_scalar *tweak) {
    secp256k1_scalar_add(key, key, tweak);
    return !secp256k1_scalar_is_zero(key);
}

int secp256k1_ec_seckey_tweak_add(unsigned char *seckey, const unsigned char *tweak) {
    secp256k1_scalar term;
    secp256k1_scalar sec;
    int ret = 0;
    int overflow = 0;
    secp256k1_scalar_set_b32(&term, tweak, &overflow);
    ret = secp256k1_scalar_set_b32_seckey(&sec, seckey);

    ret &= (!overflow) & secp256k1_eckey_privkey_tweak_add(&sec, &term);
    secp256k1_scalar secp256k1_scalar_zero = { .d = {0, 0, 0, 0, 0, 0, 0, 0} };
    secp256k1_scalar_cmov(&sec, &secp256k1_scalar_zero, !ret);
    secp256k1_scalar_get_b32(seckey, &sec);

    secp256k1_scalar_clear(&sec);
    secp256k1_scalar_clear(&term);
    return ret;
}

static int secp256k1_pubkey_load(secp256k1_ge* ge, const secp256k1_pubkey* pubkey) {
    secp256k1_fe x, y;
    secp256k1_fe_set_b32(&x, pubkey->data);
    secp256k1_fe_set_b32(&y, pubkey->data + 32);
    secp256k1_ge_set_xy(ge, &x, &y);

    return 1;
}

static int secp256k1_eckey_pubkey_serialize(secp256k1_ge *elem, unsigned char *pub, size_t *size, int compressed) {
    if (secp256k1_ge_is_infinity(elem)) {
        return 0;
    }
    secp256k1_fe_normalize_var(&elem->x);
    secp256k1_fe_normalize_var(&elem->y);
    secp256k1_fe_get_b32(&pub[1], &elem->x);
    if (compressed) {
        *size = 33;
        pub[0] = secp256k1_fe_is_odd(&elem->y) ? 0x03 : 0x02;  // SECP256K1_TAG_PUBKEY_ODD or SECP256K1_TAG_PUBKEY_EVEN
    } else {
        *size = 65;
        pub[0] = 0x04;  // SECP256K1_TAG_PUBKEY_UNCOMPRESSED
        secp256k1_fe_get_b32(&pub[33], &elem->y);
    }
    return 1;
}

int secp256k1_ec_pubkey_serialize(unsigned char *output, size_t outputlen, const secp256k1_pubkey* pubkey, unsigned int flags) {
    secp256k1_ge Q;
    int ret = 0;
    size_t size = outputlen;
    memset(output, 0, outputlen);
    if (secp256k1_pubkey_load(&Q, pubkey)) {
        ret = secp256k1_eckey_pubkey_serialize(&Q, output, &size, flags & 1);  // SECP256K1_FLAGS_BIT_COMPRESSION
    }
    return ret;
}
