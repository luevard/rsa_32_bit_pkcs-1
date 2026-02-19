#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <openssl/rand.h>
#include <sys/time.h>

typedef struct {
    uint32_t n;
    uint32_t e;
} rsa_public_key;

typedef struct {
    uint32_t n;
    uint32_t d;
} rsa_private_key;

typedef struct {
    rsa_private_key private;
    rsa_public_key public;
} rsa_keys;

// Greatest Common Divisor / PGCD
uint32_t gcd(uint32_t a, uint32_t b) {
    while (b != 0) {
        uint32_t t = b;
        b = a % b;
        a = t;
    }
    return a;
}

// Generation of an 16-bit integer with openssl function
uint16_t random_16bits() {
    uint16_t r;
    if (RAND_bytes((unsigned char *)&r, sizeof(r)) != 1) {
        fprintf(stderr, "Erreur RAND_bytes\n");
        exit(EXIT_FAILURE);
    }
    return r;
}

// Generation of an 8-bit integer different from 0 with openssl function
uint8_t random_nonzero_byte() {
    uint8_t r;
    do {
        RAND_bytes(&r, 1);
    } while (r == 0);
    return r;
}

// Modular exponentiation for extended Euclidean algorithm
uint32_t pow_mod(uint32_t base, uint32_t exp, uint32_t mod) {
    uint64_t result = 1;
    uint64_t b = base % mod;

    while (exp > 0) {
        if (exp & 1)
            result = (result * b) % mod;

        b = (b * b) % mod;
        exp >>= 1;
    }

    return (uint32_t)result;
}

// Primality test with Miller-Rabin algorithm
bool miller_rabin(uint32_t n, int k) {
    if (n < 2)
        return 0;
    if (n == 2 || n == 3)
        return 1;
    if ((n & 1) == 0)
        return 0;

    uint32_t d = n - 1;
    int s = 0;

    while ((d & 1) == 0) {
        d >>= 1;
        s++;
    }

    for (int i = 0; i < k; i++) {
        uint32_t a = 2 + random_nonzero_byte() % (n - 3);
        uint32_t x = pow_mod(a, d, n);

        if (x == 1 || x == n - 1)
            continue;
        int temoin = 1;

        for (int r = 1; r < s; r++) {
            x = (uint32_t)x * x % n;
            if (x == n - 1) {
                temoin = 0;
                break;
            }
        }
        if (temoin)
            return false;
    }
    return true;
}

// Extended Euclidean algorithm
int extended_euclidean(int a, int b, int *u, int *v) {
    if (b == 0) {
        *u = 1;
        *v = 0;
        return a;
    }

    int u1, v1;
    int d = extended_euclidean(b, a % b, &u1, &v1);

    *u = v1;
    *v = u1 - (a / b) * v1;

    return d;
}

// Encrypt a message with a public RSA key 
uint32_t rsa_encrypt(uint32_t m, rsa_public_key pb){
    return pow_mod(m, pb.e, pb.n);
}

// Decrypt a message with a private RSA key
uint32_t rsa_decrypt(uint32_t c, rsa_private_key pv){
    return pow_mod(c, pv.d, pv.n);
}

// Generate a couple of RSA key
void generate_rsa_keys(rsa_keys *keys) {
    int u, v, k = 5;
    uint16_t p, q;
    uint32_t phi, e;

    do {
        p = random_16bits();
    } while (!miller_rabin(p, k));

    do {
        q = random_16bits();
    } while (!miller_rabin(q, k) || q == p);

    uint32_t n = p * q;
    phi = (p - 1) * (q - 1);

    do {
        e = 2 + rand() % (phi - 2);
    } while (gcd(e, phi) != 1);

    extended_euclidean(e, phi, &u, &v);

    int32_t d = u % (int32_t)phi;
    if (d < 0)
        d += phi;

    keys->public.n = n;
    keys->public.e = e;
    keys->private.n = n;
    keys->private.d = (uint32_t)d;
}

// Padding function for truncated version of RSA PKCS#1 v1.5
uint32_t padding(uint16_t m){
    return
        ((uint32_t)0x02 << 24) |
        (random_nonzero_byte()   << 16) |
        ((uint32_t)0x00 << 8)  |
        (m);
}

// Unpadding function for truncated version of RSA PKCS#1 v1.5
bool unpadding(uint32_t eb, uint8_t *m){
    uint8_t bt  = (eb >> 24) & 0xFF;
    uint8_t ps  = (eb >> 16) & 0xFF;
    uint8_t zero = (eb >> 8)  & 0xFF;
    uint8_t d   = eb & 0xFF;

    if (bt != 0x02) return false;
    if (ps == 0x00) return false;
    if (zero != 0x00) return false;

    *m = d;
    return true;
}

int main(void){
    rsa_keys alice,bob;

    generate_rsa_keys(&alice);
    generate_rsa_keys(&bob);

    uint8_t value='L';
    uint32_t message = padding(value);
    uint32_t cipher = rsa_encrypt(message, bob.public);
    uint32_t decrypted = rsa_decrypt(cipher, bob.private);
    uint8_t messagedecrypted;
    printf("Valeur chiffré par ALICE : %c\n", value);
    printf("Block original avec padding  : %u\n", message);
    printf("Block chiffré: %u\n", cipher);
    if(!unpadding(decrypted,&messagedecrypted)){
        fprintf(stderr, "Erreur débourrage\n");
        exit(EXIT_FAILURE);
    }
    printf("Valeur déchiffré par BOB : %c\n",messagedecrypted);
    return 0;
}