#pragma once

class WEMKey {
    using byte = unsigned char;

    private:
        void generateRndStream(byte rndStream[], byte key[]);
        void generateBox(byte key[]);

    public:
        byte sbox[3][256];
        byte invsbox[3][256];

        WEMKey() = default;
        ~WEMKey() = default;
        WEMKey(byte key[]);
};

template <int P1 = 5, int P2 = 5>
class WEM {
    using byte = unsigned char;

    private:
        void SLayer(byte text[], const byte sbox[256]);
        void invSLayer(byte text[], const byte invsbox[256]);

    public:
        WEM() = default;
        ~WEM() = default;
        WEM(const WEM&) = delete;
        WEM(WEM&&) = delete;
        WEM& operator=(const WEM&) = delete;
        WEM operator=(const WEM&&) = delete;
        
        static const bool PN1 = 0;
        static const bool PN2 = 1;

        static WEM& instance();

        void WEMEncrypt(byte ciphertext[], const byte plaintext[], const WEMKey key);
        void WEMDecrypt(byte plaintext[], const byte ciphertext[], const WEMKey key);

        template <int PType>
        void PLayer(byte text[]);

        template <int PType>
        void invPLayer(byte text[]);
};

#include "../AES/AES128_ni.h"

#include <cstring>
#include <immintrin.h>

WEMKey::WEMKey(byte key[16]) { generateBox(key); }

inline void WEMKey::generateRndStream(byte rndStream[256 * 16 * 3], byte key[16])
{
    AESKey aesKey(key);
    AES& aesHandler = AES::instance();
    unsigned char counter[16];
    memset(counter, 0x00, 16);
    for (int i = 0; i < 256 * 3; ++i) {
        counter[14] = (i >> 8) & 0xff;
        counter[15] = i & 0xff;

        aesHandler.AESEncrypt(rndStream, counter, aesKey, 10);

        rndStream += 16;
    }
    return;
}

void WEMKey::generateBox(byte key[16])
{
    byte rndStream[256 * 16 * 3];
    generateRndStream(rndStream, key);

    int rndIndex = 0;

    for (int i = 0; i < 256; ++i) sbox[0][i] = i;
    for (int i = 256 - 1; i >= 0; --i) {
        int j = rndStream[rndIndex++] % (i + 1);
        int tmp = sbox[0][i];
        sbox[0][i] = sbox[0][j];
        sbox[0][j] = tmp;
    }

    for (int i = 0; i < 256; ++i) sbox[1][i] = i;
    for (int i = 256 - 1; i >= 0; --i) {
        int j = rndStream[rndIndex++] % (i + 1);
        int tmp = sbox[1][i];
        sbox[1][i] = sbox[1][j];
        sbox[1][j] = tmp;
    }

    for (int i = 0; i < 256; ++i) sbox[2][i] = i;
    for (int i = 256 - 1; i >= 0; --i) {
        int j = rndStream[rndIndex++] % (i + 1);
        int tmp = sbox[2][i];
        sbox[2][i] = sbox[2][j];
        sbox[2][j] = tmp;
    }

    for (int li = 0; li < 3; ++li)
        for (int i = 0; i < 256; ++i)
            invsbox[li][sbox[li][i]] = i;
    return;
}

/****************************    AES key schedule     ****************************************/
#define AES_128_key_exp(k, rcon) aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))
inline __m128i aes_128_key_expansion(__m128i key, __m128i keygened)
{
    keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3,3,3,3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygened);
}

inline void aes128_load_key(__m128i *roundkey, unsigned char masterkey[16])
{
//    unsigned char masterkey[16] = { 0x00 };

    roundkey[0] = _mm_loadu_si128((const __m128i*)masterkey);
    roundkey[1]  = AES_128_key_exp(roundkey[0], 0x01);
    roundkey[2]  = AES_128_key_exp(roundkey[1], 0x02);
    roundkey[3]  = AES_128_key_exp(roundkey[2], 0x04);
    roundkey[4]  = AES_128_key_exp(roundkey[3], 0x08);
    roundkey[5]  = AES_128_key_exp(roundkey[4], 0x10);
    roundkey[6]  = AES_128_key_exp(roundkey[5], 0x20);
    roundkey[7]  = AES_128_key_exp(roundkey[6], 0x40);
    roundkey[8]  = AES_128_key_exp(roundkey[7], 0x80);
    roundkey[9]  = AES_128_key_exp(roundkey[8], 0x1B);
    roundkey[10] = AES_128_key_exp(roundkey[9], 0x36);

    roundkey[11] = _mm_aesimc_si128(roundkey[10]);
    roundkey[12] = _mm_aesimc_si128(roundkey[9]);
    roundkey[13] = _mm_aesimc_si128(roundkey[8]);
    roundkey[14] = _mm_aesimc_si128(roundkey[7]);
    roundkey[15] = _mm_aesimc_si128(roundkey[6]);
    roundkey[16] = _mm_aesimc_si128(roundkey[5]);
    roundkey[17] = _mm_aesimc_si128(roundkey[4]);
    roundkey[18] = _mm_aesimc_si128(roundkey[3]);
    roundkey[19] = _mm_aesimc_si128(roundkey[2]);
    roundkey[20] = _mm_aesimc_si128(roundkey[1]);

    return;
}

template <int P1, int P2>
WEM<P1, P2>& WEM<P1, P2>::instance()
{
    static WEM<P1, P2> WEMINSTANCE;
    return WEMINSTANCE;
}

template <int P1, int P2>
void WEM<P1, P2>::SLayer(byte text[16], const byte sbox[256])
{
    byte tmp[16];
    for (int i = 0; i < 16; ++i)
        tmp[i] = sbox[text[i]];
    memcpy(text, tmp, 16);
    return;
}

template <int P1, int P2>
void WEM<P1, P2>::invSLayer(byte text[16], const byte invsbox[256])
{
    byte tmp[16];
    for (int i = 0; i < 16; ++i)
        tmp[i] = invsbox[text[i]];
    memcpy(text, tmp, 16);
    return;
}

template <int P1, int P2>
template <int PType>
void WEM<P1, P2>::PLayer(byte text[16])
{
    unsigned char pkey[16];
    __m128i k[21];
    auto m = _mm_loadu_si128((__m128i *)text);

    if constexpr (PType == PN1) {
        memset(pkey, 0x00, 16);
        aes128_load_key(k, pkey);
        m = _mm_xor_si128(m, k[0]);
        for (int i = 1; i <= P1; ++i)
            m = _mm_aesenc_si128(m, k[i]);
    } else {
        memset(pkey, 0x01, 16);
        aes128_load_key(k, pkey);
        m = _mm_xor_si128(m, k[0]);
        for (int i = 1; i <= P2; ++i)
            m = _mm_aesenc_si128(m, k[i]);
    }

    _mm_storeu_si128((__m128i *)text, m);
    return;
}

template <int P1, int P2>
template <int PType>
void WEM<P1, P2>::invPLayer(byte text[16])
{
    unsigned char pkey[16];
    __m128i k[21];

    auto m = _mm_loadu_si128((__m128i *)text);
    auto tmpK = m;
    m = _mm_aesenclast_si128(m, tmpK);

    m = _mm_xor_si128(m, tmpK);
    if constexpr (PType == PN1) {
        memset(pkey, 0x00, 16);
        aes128_load_key(k, pkey);
        for (int i = 21 - P1; i < 21; ++i)
            m = _mm_aesdec_si128(m, k[i]);
        m = _mm_aesdeclast_si128(m, k[0]);
    } else {
        memset(pkey, 0x01, 16);
        aes128_load_key(k, pkey);
        for (int i = 21 - P2; i < 21; ++i)
            m = _mm_aesdec_si128(m, k[i]);
        m = _mm_aesdeclast_si128(m, k[0]);
    }

    _mm_storeu_si128((__m128i *)text, m);
    return;
}

template <int P1, int P2>
void WEM<P1, P2>::WEMEncrypt(byte ciphertext[16], const byte plaintext[16], const WEMKey key)
{
    memcpy(ciphertext, plaintext, 16);
    SLayer(ciphertext, key.sbox[0]);
    PLayer<PN1>(ciphertext);
    SLayer(ciphertext, key.sbox[0]);
    PLayer<PN2>(ciphertext);
    SLayer(ciphertext, key.sbox[0]);
    return;
}

template <int P1, int P2>
void WEM<P1, P2>::WEMDecrypt(byte plaintext[16], const byte ciphertext[16], const WEMKey key)
{
    memcpy(plaintext, ciphertext, 16);
    invSLayer(plaintext, key.invsbox[0]);
    invPLayer<PN2>(plaintext);
    invSLayer(plaintext, key.invsbox[0]);
    invPLayer<PN1>(plaintext);
    invSLayer(plaintext, key.invsbox[0]);
    return;
}

