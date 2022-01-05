#include "crypto/AES/AES128_ni.h"
#include "crypto/GF/GF28.h"
#include "crypto/utils/component.h"

#include <iostream>
#include <iomanip>
#include <cstring>
#include <string>
#include <bitset>
#include <vector>
#include <functional>
#include <random>
#include <algorithm>
#include <queue>
#include <cassert>
#include <array>
#include <chrono>

#include "z3++.h"

using namespace std;

constexpr int VARNUM = 256;
constexpr int QNUM = 256;
constexpr int nrand = 10000;

static void printx(const unsigned char s[4])
{
    std::cout << std::hex;
    for (int i = 0; i < 4; ++i) {
        std::cout << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(s[i]) << ' ';
    }
    std::cout << std::dec;
    return;
}

static void printx(const std::array<unsigned char, 4> s)
{
    std::cout << std::hex;
    for (int i = 0; i < 4; ++i) {
        std::cout << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(s[i]) << ' ';
    }
    std::cout << std::dec;
    return;
}


static void generateMatrix(unsigned char mat[32][4])
{
    unsigned int m[32];
    for (int i = 0; i < 32; ++i)
        m[i] = (1 << i);

    random_device rd;
    default_random_engine randomGen(rd());
    uniform_int_distribution<int> dist(0, 31);

    for (int i = 0; i < nrand; ++i) {
        // swap
        int row1 = static_cast<int>(dist(randomGen));
        int row2 = static_cast<int>(dist(randomGen));
        int tmp = m[row1];
        m[row1] = m[row2];
        m[row2] = tmp;

        // add
        row1 = static_cast<int>(dist(randomGen));
        row2 = static_cast<int>(dist(randomGen));
        if (row1 == row2) continue;
        m[row1] = m[row1] ^ m[row2];
    }

    memcpy(mat, m, 32 * 4);

    return;
}

static void supersbox(unsigned char ciphertext[4], const unsigned char plaintext[4], const unsigned char mat[32][4], const unsigned char invsbox[256])
{
    auto invAESSbox = component::getAESInvSbox();

    memcpy(ciphertext, plaintext, 4);

    // inv affine A
    unsigned int ciphernum = 0;
    for (int row = 32 - 1; row >= 0; --row) {
        unsigned char bit = mat[row][0] & ciphertext[0];
        bit ^= mat[row][1] & ciphertext[1];
        bit ^= mat[row][2] & ciphertext[2];
        bit ^= mat[row][3] & ciphertext[3];

        bit ^= (bit >> 4);
        bit ^= (bit >> 2);
        bit ^= (bit >> 1);

        ciphernum = (ciphernum << 1) | (bit & 1);
    }
    ciphertext[0] = (ciphernum >>  0) & 0xff;
    ciphertext[1] = (ciphernum >>  8) & 0xff;
    ciphertext[2] = (ciphernum >> 16) & 0xff;
    ciphertext[3] = (ciphernum >> 24) & 0xff;

    // inv aes sbox
    for (int i = 0; i < 4; ++i) ciphertext[i] = invAESSbox[ciphertext[i]];

    // inv ark1
    ciphertext[0] ^= 0x62;
    ciphertext[1] ^= 0x63;
    ciphertext[2] ^= 0x63;
    ciphertext[3] ^= 0x63;

    // inv mc
    unsigned char state[4];
    memcpy(state, ciphertext, 4);

    const unsigned char tmpState = state[0] ^ state[1] ^ state[2] ^ state[3];
    ciphertext[0] = state[0] ^ GF28::mul(0x09, tmpState) ^ GF28::mul(0x04, state[0] ^ state[2]) ^ GF28::mul(0x02, state[0] ^ state[1]);
    ciphertext[1] = state[1] ^ GF28::mul(0x09, tmpState) ^ GF28::mul(0x04, state[1] ^ state[3]) ^ GF28::mul(0x02, state[1] ^ state[2]);
    ciphertext[2] = state[2] ^ GF28::mul(0x09, tmpState) ^ GF28::mul(0x04, state[0] ^ state[2]) ^ GF28::mul(0x02, state[2] ^ state[3]);
    ciphertext[3] = state[3] ^ GF28::mul(0x09, tmpState) ^ GF28::mul(0x04, state[1] ^ state[3]) ^ GF28::mul(0x02, state[3] ^ state[0]);


    // inv aes sbox
    for (int i = 0; i < 4; ++i) ciphertext[i] = invAESSbox[ciphertext[i]];

    // inv secret sbox
    for (int i = 0; i < 4; ++i) ciphertext[i] = invsbox[ciphertext[i]];

    return;
}

static void checkcheck(const vector< array<unsigned char, 4> > cs, const unsigned char mat[32][4], const unsigned char invsbox[256])
{
    unsigned char tmpSum[4] = { 0x00, 0x00, 0x00, 0x00 };
    unsigned char ciphertext[4];
    int cnt[4][256];
    memset(cnt, 0, 4 * 256 * 4);

    for (auto &c : cs) {
        ciphertext[0] = c[0];
        ciphertext[1] = c[1];
        ciphertext[2] = c[2];
        ciphertext[3] = c[3];
    
        // inv affine A
        unsigned int ciphernum = 0;
        for (int row = 32 - 1; row >= 0; --row) {
            unsigned char bit = mat[row][0] & ciphertext[0];
            bit ^= mat[row][1] & ciphertext[1];
            bit ^= mat[row][2] & ciphertext[2];
            bit ^= mat[row][3] & ciphertext[3];
    
            bit ^= (bit >> 4);
            bit ^= (bit >> 2);
            bit ^= (bit >> 1);
    
            ciphernum = (ciphernum << 1) | (bit & 1);
        }
        ciphertext[0] = (ciphernum >>  0) & 0xff;
        ciphertext[1] = (ciphernum >>  8) & 0xff;
        ciphertext[2] = (ciphernum >> 16) & 0xff;
        ciphertext[3] = (ciphernum >> 24) & 0xff;
    
        /*
        // inv aes sbox
        auto invAESSbox = component::getAESInvSbox();
        for (int i = 0; i < 4; ++i) ciphertext[i] = invAESSbox[ciphertext[i]];
    
        // inv ark1
        ciphertext[0] ^= 0x62;
        ciphertext[1] ^= 0x63;
        ciphertext[2] ^= 0x63;
        ciphertext[3] ^= 0x63;
    
        // inv mc
        unsigned char state[4];
        memcpy(state, ciphertext, 4);
    
        const unsigned char tmpState = state[0] ^ state[1] ^ state[2] ^ state[3];
        ciphertext[0] = state[0] ^ GF28::mul(0x09, tmpState) ^ GF28::mul(0x04, state[0] ^ state[2]) ^ GF28::mul(0x02, state[0] ^ state[1]);
        ciphertext[1] = state[1] ^ GF28::mul(0x09, tmpState) ^ GF28::mul(0x04, state[1] ^ state[3]) ^ GF28::mul(0x02, state[1] ^ state[2]);
        ciphertext[2] = state[2] ^ GF28::mul(0x09, tmpState) ^ GF28::mul(0x04, state[0] ^ state[2]) ^ GF28::mul(0x02, state[2] ^ state[3]);
        ciphertext[3] = state[3] ^ GF28::mul(0x09, tmpState) ^ GF28::mul(0x04, state[1] ^ state[3]) ^ GF28::mul(0x02, state[3] ^ state[0]);
    
    
        // inv aes sbox
        for (int i = 0; i < 4; ++i) ciphertext[i] = invAESSbox[ciphertext[i]];
    
        // inv secret sbox
        for (int i = 0; i < 4; ++i) ciphertext[i] = invsbox[ciphertext[i]];
        */

        tmpSum[0] ^= ciphertext[0];
        tmpSum[1] ^= ciphertext[1];
        tmpSum[2] ^= ciphertext[2];
        tmpSum[3] ^= ciphertext[3];

        ++cnt[0][ciphertext[0]];
        ++cnt[1][ciphertext[1]];
        ++cnt[2][ciphertext[2]];
        ++cnt[3][ciphertext[3]];

        printx(ciphertext); cout << endl;
    }

    if (tmpSum[0] || tmpSum[1] || tmpSum[2] || tmpSum[3])
        cout << "not zero sum" << endl;
    for (int i = 0; i < 4; ++i) {
        bool isP = true;
        bool isC = true;

        for (int j = 0x00; j <= 0xff; ++j) {
            cout << cnt[i][j] << ' ';
            if (cnt[i][j] > 1) isP = false;
            if (cnt[i][j] > 0 && cnt[i][j] < 256) isC = false;
        }

        if (isP) cout << "P ";
        else if (isC) cout << "C ";
        else cout << "U ";

        cout << endl;
    }
    cout << endl;
    return;
}

static void info(string s)
{
    return;
    static int steps;
    cout << "[" << steps << "] " << s << endl;
    ++steps;
    return;
}

bool recoverSbox(unsigned char secretKey[16])
{
    info("Setup oracle");

    unsigned char mat[32][4];
    generateMatrix(mat);

    unsigned char ssb[256];
    unsigned char invssb[256];
    component::generateBox(ssb, invssb, secretKey, 0);

    auto oracle = bind(&supersbox, placeholders::_1, placeholders::_2, mat, invssb); // decryption oracle

    info("Start Attack");
    bitset<VARNUM> eqs[QNUM];
    vector< array<unsigned char, 4> > ps[QNUM];
    vector< array<unsigned char, 4> > cs[QNUM];

    for (int j = 0; j < QNUM; ++j)
        eqs[j].reset();

    info("Query oracle");
    unsigned char plaintext[4];
    unsigned char ciphertext[4];
    int eqCnt = 0;
    while (eqCnt < QNUM - 4) {
        ciphertext[1] = static_cast<unsigned char>((eqCnt + 0) & 0xdd); // randomly choose
        ciphertext[2] = static_cast<unsigned char>((eqCnt + 1) & 0xee); // randomly choose
        ciphertext[3] = static_cast<unsigned char>((eqCnt + 2) & 0xff); // randomly choose

        for (int j = 0x00; j <= 0xff; ++j) {
            ciphertext[0] = static_cast<unsigned char>(j & 0xff);
            
            oracle(plaintext, ciphertext);

            for (int b = 0; b < 4; ++b)
                eqs[eqCnt + b].flip(plaintext[b]);

            array<unsigned char, 4>  tmpArray;
            for (int tt = 0; tt < 4; ++tt) tmpArray[tt] = plaintext[tt];
            ps[eqCnt / 4].push_back(tmpArray);

            array<unsigned char, 4>  tmpArray2;
            for (int tt = 0; tt < 4; ++tt) tmpArray2[tt] = ciphertext[tt];
            cs[eqCnt / 4].push_back(tmpArray2);
        }

        eqCnt += 4;
    }

    info("Gauss Elimination");
    int rank = 0;
    eqs[0].flip();
    for (int col = 0, firstRow = 0; col < VARNUM; ++col) {
        bool hasOne = false;

        for (int row = firstRow; row < QNUM; ++row)
            if (eqs[row].test(col)) {
                auto tmp = eqs[row];
                eqs[row] = eqs[firstRow];
                eqs[firstRow] = tmp;
                hasOne = true;
                break;
            }

        if (!hasOne) continue;

        ++rank;
        for (int row = 0; row < QNUM; ++row)
            if (eqs[row].test(col) && row != firstRow)
                eqs[row] = eqs[row] ^ eqs[firstRow];

        ++firstRow;
    }
    // Triangle form
    int oneRow;
    for (oneRow = VARNUM - 1; oneRow >= 0; --oneRow)
        if (eqs[oneRow].any()) break;
    while (!eqs[oneRow].test(oneRow)) {
        for (int i = oneRow - 1; i < 256; ++i)
            if (eqs[oneRow].test(i)) {
                auto tmp = eqs[i];
                eqs[i] = eqs[oneRow];
                eqs[oneRow] = tmp;
                break;
            }

        --oneRow;
    }

    for (int i = 0; i < 256; ++i) {
        auto aesSbox = component::getAESSbox();
        unsigned char tmp = 0x00;
        for (int j = 0; j < 256; ++j)
            tmp ^= aesSbox[ssb[j]];

        if (tmp != 0x00)
            return 0;
    }

    //cout << "rank: " << rank << endl;

    info("Find one Sbox solution using Z3");
    z3::context z3ctx;
    z3::expr_vector z3p(z3ctx);
    for (int i = 0; i < VARNUM; ++i) {
        stringstream p_name;
        p_name << "p_" << i;
        z3p.push_back(z3ctx.bv_const(p_name.str().c_str(), 8));
    }
    z3::solver z3solver(z3ctx);
    z3solver.add(z3::distinct(z3p));

    for (int i = 0; i < VARNUM; ++i) {
        if (!eqs[i].test(i)) continue;

        auto z3tmp = z3p[i];
        for (int j = i + 1; j < VARNUM; ++j)
            if (eqs[i].test(j)) {
                z3tmp = z3::to_expr(z3ctx, z3tmp ^ z3p[j]);
            }
        z3solver.add(z3tmp == 0);
    }

    auto isSat = z3solver.check();
//    assert(isSat == z3::sat);
    if (isSat != z3::sat)
        return false;

    auto z3m = z3solver.get_model();
    
    unsigned char S[VARNUM];
    for (int i = 0; i < VARNUM; ++i) {
        unsigned int tmpUint;
        Z3_get_numeral_uint(z3ctx, z3m.eval(z3p[i]), &tmpUint);
        S[i] = tmpUint & 0xff;
    }

    for (int i = 0; i < QNUM; ++i) {
        unsigned char tmpSum[4] = { 0x00, 0x00, 0x00, 0x00 };
        for (auto &plain : ps[i]) {
            tmpSum[0] ^= S[plain[0]];
            tmpSum[1] ^= S[plain[1]];
            tmpSum[2] ^= S[plain[2]];
            tmpSum[3] ^= S[plain[3]];
        }

        if (tmpSum[0] || tmpSum[1] || tmpSum[2] || tmpSum[3]) {
            cout << "error" << endl;
            return false;
        }
    }

    info("Generate D' (before MC)");
    unsigned char D[QNUM][4 * 256];
    for (int i = 0; i < QNUM; ++i) {
        int tmpIndex = 0;
        for (auto &plain : ps[i]) {
            D[i][tmpIndex + 0] = S[plain[0]];
            D[i][tmpIndex + 1] = S[plain[1]];
            D[i][tmpIndex + 2] = S[plain[2]];
            D[i][tmpIndex + 3] = S[plain[3]];
            tmpIndex += 4;
        }
    }

    info("Determine affine transformation");
    int A[8];
    A[0] = 0x80;

    queue<int> aCandidate;
    for (int ai = 1; ai < 8; ++ai) {
        for (int i = 0; i < 256; ++i) aCandidate.push(i);
    
        for (int qi = 0; qi < QNUM; ++qi) {
            aCandidate.push(-1);
            while (aCandidate.front() != -1) {
                int cur = aCandidate.front();
                aCandidate.pop();
    
                int zero = 0, one = 0;
                for (int i = 0; i < 4 * VARNUM; i += 4) {
                    int tmpBit = cur & (D[qi][i] ^ D[qi][i + 1]);
                    tmpBit ^= A[ai - 1] & (D[qi][i + 1] ^ D[qi][i + 2] ^ D[qi][i + 3]);
                    if (ai == 4 || ai == 5 || ai == 7)
                        tmpBit ^= A[0] & (D[qi][i] ^ D[qi][i + 1]);
                    tmpBit = ((tmpBit >> 0) & 1)
                           ^ ((tmpBit >> 1) & 1)
                           ^ ((tmpBit >> 2) & 1)
                           ^ ((tmpBit >> 3) & 1)
                           ^ ((tmpBit >> 4) & 1)
                           ^ ((tmpBit >> 5) & 1)
                           ^ ((tmpBit >> 6) & 1)
                           ^ ((tmpBit >> 7) & 1);
    
                    tmpBit? ++one : ++zero;
                }
                if (one == zero) aCandidate.push(cur);
            }
            aCandidate.pop(); // pop -1
    
            if (aCandidate.size() <= 1) break;
        }

        //assert(aCandidate.size() == 1);
        if (aCandidate.size() != 1) {
//            cout << "candidates: " << aCandidate.size() << endl;
            return false;
        }

        A[ai] = aCandidate.front();
        aCandidate.pop();
    }

    //cout << "A: [" << endl;
    //for (int i = 0; i < 8; ++i) cout << std::hex << setw(2) << setfill('0') << A[i] << ": " << bitset<8>(A[i]) << endl;
    //cout << "]" << std::dec << endl;

    for (int i = 0; i < 256; ++i) {
        unsigned char Sbit = 0x00;
        for (int j = 0; j < 8; ++j) {
            int tmpBit = A[j] & S[i];

            tmpBit = ((tmpBit >> 0) & 1)
                   ^ ((tmpBit >> 1) & 1)
                   ^ ((tmpBit >> 2) & 1)
                   ^ ((tmpBit >> 3) & 1)
                   ^ ((tmpBit >> 4) & 1)
                   ^ ((tmpBit >> 5) & 1)
                   ^ ((tmpBit >> 6) & 1)
                   ^ ((tmpBit >> 7) & 1);

            Sbit = (Sbit << 1) | tmpBit;
        }

        S[i] = Sbit;
    }

    //cout << "S': " << endl << "[ ";
    //for (int i = 0; i < VARNUM; ++i) cout << '(' << std::hex << setw(2) << setfill('0') << i << ": " << setw(2) << setfill('0') << static_cast<unsigned int>(S[i]) << "), ";
    //cout << "]" << std::dec << endl;

    auto aesSbox = component::getAESSbox();

    unsigned char a = GF28::mul(S[0] ^ S[1], GF28::inv(aesSbox[ssb[0]] ^ aesSbox[ssb[1]]));
    unsigned char b = S[0] ^ GF28::mul(a, aesSbox[ssb[0]]);

    for (int i = 0; i < 256; ++i) {
        unsigned char tmps = GF28::mul(a, aesSbox[ssb[i]]) ^ b;
        if (S[i] != tmps)
            //cout << "error" << endl;
            return false;
    }

    return true;
}

int main()
{
    random_device rd;
    default_random_engine randomGen(rd());
    uniform_int_distribution<int> dist(0, 255);
    unsigned char secretKey[16];
    for (int i = 0; i < 16; ++i) secretKey[i] = static_cast<unsigned char>(dist(randomGen));

    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < 1000; ++i) {
        bool isSolved = recoverSbox(secretKey);
        if (isSolved)
            break;
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    cout << "duration: " << duration << endl;

    return 0;
}

