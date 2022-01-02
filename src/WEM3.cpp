#include "crypto/WEM/WEM_2EM.hpp"
#include "crypto/GF/GF28.h"
#include "crypto/utils/component.h"

#include <iostream>
#include <cstring>
#include <string>
#include <functional>
#include <random>
#include <cassert>

using std::cout;
using std::endl;

using component::printx;

constexpr int eqNum = 1 + (1 << 9); // 1 for the special equation

static void info(std::string s)
{
    return;
    static int steps;
    cout << "[" << steps << "] " << s << endl;
    ++steps;
    return;
}

constexpr int eqSize = 256;
inline void swapEq(unsigned char *eq1, unsigned char *eq2)
{
    unsigned char tmp[eqSize];
    memcpy(tmp, eq1, eqSize);
    memcpy(eq1, eq2, eqSize);
    memcpy(eq2, tmp, eqSize);
    return;
}
inline void xorEq(unsigned char *eq, unsigned char *eq1, unsigned char *eq2)
{
    unsigned char tmp[eqSize];
    for (int i = 0; i < eqSize; ++i)
        tmp[i] = eq1[i] ^ eq2[i];
    memcpy(eq, tmp, eqSize);
    return;
}
inline void mulEq(unsigned char *eq, unsigned char *eq1, unsigned char c)
{
    unsigned char tmp[eqSize];
    for (int i = 0; i < eqSize; ++i)
        tmp[i] = GF28::mul(eq1[i], c);
    memcpy(eq, tmp, eqSize);
    return;
}
int solveLinear(unsigned char linearEqs[eqNum][eqSize])
{
    int rank = 0;
    for (int col = 0, firstRow = 0; col < eqSize; ++col) {
        bool hasOne = false;

        for (int row = firstRow; row < eqNum; ++row)
            if (linearEqs[row][col]) {
                swapEq(linearEqs[firstRow], linearEqs[row]);
                hasOne = true;
                break;
            }

        if (!hasOne) continue;

        ++rank;
        auto pivot = linearEqs[firstRow][col];
        auto invPivot = GF28::inv(pivot);
        mulEq(linearEqs[firstRow], linearEqs[firstRow], invPivot);

        for (int row = 0; row < eqNum; ++row)
            if (linearEqs[row][col] && row != firstRow) {
                unsigned char tmp[eqSize];
                mulEq(tmp, linearEqs[firstRow], linearEqs[row][col]);
                xorEq(linearEqs[row], linearEqs[row], tmp);
            }

        ++firstRow;
    }

    // Triangle form
    int oneRow;
    for (oneRow = eqSize - 1; oneRow >= 0; --oneRow) {
        bool isAny = false;
        for (int col = 0; col < eqSize; ++col)
            if (linearEqs[oneRow][col]) {
                isAny = true;
                break;
            }
        if (isAny) break;
    }
    while (!linearEqs[oneRow][oneRow]) {
        for (int i = oneRow - 1; i < eqSize; ++i)
            if (linearEqs[oneRow][i]) {
                swapEq(linearEqs[i], linearEqs[oneRow]);
                break;
            }

        --oneRow;
    }

    return rank;
}

int main()
{
    info("Setup oracle");
    std::random_device rd;
    std::default_random_engine randomGen(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    unsigned char secretKey[16];
    for (int i = 0; i < 16; ++i) secretKey[i] = static_cast<unsigned char>(dist(randomGen));

    WEMKey wemKey(secretKey);
    auto& wemHandler = WEM<1, 2>::instance();
    auto oracle = std::bind(&WEM<1, 2>::WEMEncrypt, std::ref(wemHandler), std::placeholders::_1, std::placeholders::_2, wemKey);
    auto p1Oracle  = std::bind(&WEM<1, 2>::PLayer<0>, std::ref(wemHandler), std::placeholders::_1);
    auto p2Oracle  = std::bind(&WEM<1, 2>::PLayer<1>, std::ref(wemHandler), std::placeholders::_1);

    //auto& wemHandler = WEM<2, 1>::instance();
    //auto oracle = std::bind(&WEM<2, 1>::WEMEncrypt, std::ref(wemHandler), std::placeholders::_1, std::placeholders::_2, wemKey);
    //auto p1Oracle  = std::bind(&WEM<2, 1>::PLayer<0>, std::ref(wemHandler), std::placeholders::_1);
    //auto p2Oracle  = std::bind(&WEM<2, 1>::PLayer<1>, std::ref(wemHandler), std::placeholders::_1);


    cout << endl << "===== test vector =====" << endl;
    unsigned char testvector[] = { '-', '#', '-', ' ', 'c', 'o', 'r', 'r', 'e', 'c', 't', '!', ' ', '-', '#', '-' };
    wemHandler.WEMEncrypt(testvector, testvector, wemKey);
    printx(testvector); cout << endl;
    wemHandler.WEMDecrypt(testvector, testvector, wemKey);
    for (int _vi = 0; _vi < 16; ++_vi) { cout << testvector[_vi]; } cout << endl;
    cout << "====== end  test ======" << endl << endl;


    info("Start Attack");

    info("Query oracle");
    unsigned char eqs[eqNum][256];
    memset(eqs, 0x00, sizeof(eqs));

    unsigned char plaintext[16];
    for (int i = 0; i < 16; ++i) plaintext[i] = static_cast<unsigned char>(dist(randomGen));

    int ocnt = 0;
    for (int j = 0; j < 256; ++j) eqs[0][j] = 0x01;
    for (int firstEq = 1, i = 1; i < eqNum / 4; ++i) {
        unsigned char ciphertext[16];
        if (i % 256 == 0) {
            plaintext[ 2] = static_cast<unsigned char>(dist(randomGen));
            plaintext[ 7] = static_cast<unsigned char>(dist(randomGen));
        }

        plaintext[0] = (i - 1) & 0xff;
        plaintext[5] = (i - 1) & 0xff;
        oracle(ciphertext, plaintext);
        ++ocnt;

        eqs[firstEq + 0][ciphertext[0]] ^= 0x0d;
        eqs[firstEq + 0][ciphertext[1]] ^= 0x09;
        eqs[firstEq + 0][ciphertext[2]] ^= 0x0e;
        eqs[firstEq + 0][ciphertext[3]] ^= 0x0b;

        eqs[firstEq + 1][ciphertext[4]] ^= 0x09;
        eqs[firstEq + 1][ciphertext[5]] ^= 0x0e;
        eqs[firstEq + 1][ciphertext[6]] ^= 0x0b;
        eqs[firstEq + 1][ciphertext[7]] ^= 0x0d;

        eqs[firstEq + 2][ciphertext[8]] ^= 0x0e;
        eqs[firstEq + 2][ciphertext[9]] ^= 0x0b;
        eqs[firstEq + 2][ciphertext[10]] ^= 0x0d;
        eqs[firstEq + 2][ciphertext[11]] ^= 0x09;

        eqs[firstEq + 3][ciphertext[12]] ^= 0x0b;
        eqs[firstEq + 3][ciphertext[13]] ^= 0x0d;
        eqs[firstEq + 3][ciphertext[14]] ^= 0x09;
        eqs[firstEq + 3][ciphertext[15]] ^= 0x0e;

        plaintext[0] = i & 0xff;
        plaintext[5] = i & 0xff;
        oracle(ciphertext, plaintext);
        ++ocnt;

        eqs[firstEq + 0][ciphertext[0]] ^= 0x0d;
        eqs[firstEq + 0][ciphertext[1]] ^= 0x09;
        eqs[firstEq + 0][ciphertext[2]] ^= 0x0e;
        eqs[firstEq + 0][ciphertext[3]] ^= 0x0b;

        eqs[firstEq + 1][ciphertext[4]] ^= 0x09;
        eqs[firstEq + 1][ciphertext[5]] ^= 0x0e;
        eqs[firstEq + 1][ciphertext[6]] ^= 0x0b;
        eqs[firstEq + 1][ciphertext[7]] ^= 0x0d;

        eqs[firstEq + 2][ciphertext[8]] ^= 0x0e;
        eqs[firstEq + 2][ciphertext[9]] ^= 0x0b;
        eqs[firstEq + 2][ciphertext[10]] ^= 0x0d;
        eqs[firstEq + 2][ciphertext[11]] ^= 0x09;

        eqs[firstEq + 3][ciphertext[12]] ^= 0x0b;
        eqs[firstEq + 3][ciphertext[13]] ^= 0x0d;
        eqs[firstEq + 3][ciphertext[14]] ^= 0x09;
        eqs[firstEq + 3][ciphertext[15]] ^= 0x0e;

        firstEq += 4;
    }

    cout << ocnt << " queries" << endl;

    info("Gauss Elimination");
    int rank = solveLinear(eqs);
    cout << "rank: " << rank << endl;

    for (int row = 0; row < 256; ++row) {
        unsigned char res = 0x00;
        for (int col = 0; col < 256; ++col) {
            if (eqs[row][col])
                res ^= GF28::mul(eqs[row][col], wemKey.invsbox[0][col]);
        }
        if (res != 0x00) {
            cout << "error" << endl;
            return 0;
        }
    }

    int pos0 = -1;
    int pos1 = -1;
    for (int row = 0; row < 256; ++row) {
        if (eqs[row][row] == 0) {
            if (pos0 == -1) pos0 = row;
            else {
                pos1 = row;
                break;
            }
        }

        if (pos0 != -1 && pos1 != -1) break;
    }

    unsigned char zeroText[16] = { 0x00 };
    unsigned char filter[16];
    oracle(filter, zeroText);

    unsigned char recovered[256];
    recovered[pos0] = 0x00;
    recovered[pos1] = 0x01;
    for (int row = 0; row < 256; ++row) {
        if (eqs[row][row] == 0) continue;

        unsigned char z = eqs[row][pos1]; // GF28::mul(eqs[row][pos0], 0x00) ^ GF28::mul(eqs[row][pos1], 0x01);
        recovered[row] = z;
    }

    int cnt = 0;
    for (int c0 = 0x00; c0 <= 0xff; ++c0) {
        for (int c1 = 0x00; c1 <= 0xff; ++c1) {
            if (c0 == c1) continue;

            bool isTaken[256];
            memset(isTaken, 0, sizeof(isTaken));
            isTaken[c0] = 1;
            isTaken[c1] = 1;

            recovered[pos0] = c0;
            recovered[pos1] = c1;

            bool isFound = true;
            for (int row = 0; row < 256; ++row) {
                if (eqs[row][row] == 0) continue;

                unsigned char z = GF28::mul(eqs[row][pos0], c0) ^ GF28::mul(eqs[row][pos1], c1);
                if (isTaken[z]) {
                    isFound = false;
                    break;
                }
                isTaken[z] = 1;

                recovered[row] = z;
            }
            if (!isFound) continue;

            unsigned char rec[256];
            for (int i = 0x00; i <= 0xff; ++i)
                rec[recovered[i]] = i & 0xff;
            memcpy(recovered, rec, 256);

            for (int ti = 0; ti < 16; ++ti) zeroText[ti] = recovered[0x00];
            p1Oracle(zeroText);
            component::SB(zeroText, recovered);
            p2Oracle(zeroText);
            component::SB(zeroText, recovered);

            for (int ti = 0; ti < 16; ++ti)
                if (zeroText[ti] != filter[ti]) {
                    isFound = false;
                    break;
                }
            if (!isFound) continue;

            ++cnt;
            for (int sbi = 0; sbi < 256; ++sbi)
                if (recovered[sbi] != wemKey.sbox[0][sbi]) {
                    cout << "error" << endl;
                    return 0;
                }
        }
    }
    
    cout << "finish" << endl;
    cout << "number of solutions: " << cnt << endl;

    return 0;
}

