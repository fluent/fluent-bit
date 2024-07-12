
#include "aes.h"

// Main Functions
unsigned char* aes_128_encrypt(unsigned char* in, unsigned char* out, unsigned char* key)
{
    unsigned char* w;
    unsigned char Nk = 4, Nr = 10;
    w = (unsigned char*)malloc(16 * (Nr + 1));
    KeyExpansion(key, w, Nk, Nr);
    Cipher(in, out, w, Nk, Nr);
    free(w);
    return out;
}

unsigned char* aes_128_decrypt(unsigned char* in, unsigned char* out, unsigned char* key)
{
    unsigned char* w;
    unsigned char Nk = 4, Nr = 10;
    w = (unsigned char*)malloc(16 * (Nr + 1));
    KeyExpansion(key, w, Nk, Nr);
    InvCipher(in, out, w, Nk, Nr);
    free(w);
    return out;
}

unsigned char* aes_192_encrypt(unsigned char* in, unsigned char* out, unsigned char* key)
{
    unsigned char* w;
    unsigned char Nk = 6, Nr = 12;
    w = (unsigned char*)malloc(16 * (Nr + 1));
    KeyExpansion(key, w, Nk, Nr);
    Cipher(in, out, w, Nk, Nr);
    free(w);
    return out;
}

unsigned char* aes_192_decrypt(unsigned char* in, unsigned char* out, unsigned char* key)
{
    unsigned char* w;
    unsigned char Nk = 6, Nr = 12;
    w = (unsigned char*)malloc(16 * (Nr + 1));
    KeyExpansion(key, w, Nk, Nr);
    InvCipher(in, out, w, Nk, Nr);
    free(w);
    return out;
}

unsigned char* aes_256_encrypt(unsigned char* in, unsigned char* out, unsigned char* key)
{
    unsigned char* w;
    unsigned char Nk = 8, Nr = 14;
    w = (unsigned char*)malloc(16 * (Nr + 1));
    KeyExpansion(key, w, Nk, Nr);
    Cipher(in, out, w, Nk, Nr);
    free(w);
    return out;
}

unsigned char* aes_256_decrypt(unsigned char* in, unsigned char* out, unsigned char* key)
{
    unsigned char* w;
    unsigned char Nk = 8, Nr = 14;
    w = (unsigned char*)malloc(16 * (Nr + 1));
    KeyExpansion(key, w, Nk, Nr);
    InvCipher(in, out, w, Nk, Nr);
    free(w);
    return out;
}

void Cipher(unsigned char* in, unsigned char* out, unsigned char* w, unsigned char Nk, unsigned char Nr)
{
    unsigned char state[4][4];
    int i, j, round;

    // Copy input to the state array
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            state[j][i] = in[i * 4 + j];
        }
    }

    // Perform the encryption process
    AddRoundKey(state, w);
    for (round = 1; round < Nr; ++round) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, w + round * 16);
    }
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, w + Nr * 16);

    // Copy the state array to the output
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            out[i * 4 + j] = state[j][i];
        }
    }
}

void InvCipher(unsigned char* in, unsigned char* out, unsigned char* w, unsigned char Nk, unsigned char Nr)
{
    unsigned char state[4][4];
    int i, j, round;

    // Copy input to the state array
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            state[j][i] = in[i * 4 + j];
        }
    }

    AddRoundKey(state, w + Nr * 16);
    for (round = Nr - 1; round >= 1; --round) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, w + round * 16);
        InvMixColumns(state);
    }
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, w);

    // Copy the state array to the output
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            out[i * 4 + j] = state[j][i];
        }
    }
}

// Key Expansion
void KeyExpansion(unsigned char* key, unsigned char* w, unsigned char Nk, unsigned char Nr)
{
    unsigned char tmp[4];
    memcpy(w, key, 4 * Nk);

    for (int i = 4 * Nk; i < 4 * (Nr + 1) * 4; i += 4) {
        memcpy(tmp, w + i - 4, 4);
        if (i % (Nk * 4) == 0) {
            SubWord(RotWord(tmp));
            for (int j = 0; j < 4; j++) {
                tmp[j] ^= Rcon[i / Nk + j];
            }
        } else if (Nk > 6 && (i % (Nk * 4)) == 16) {
            SubWord(tmp);
        }
        for (int j = 0; j < 4; j++)
        w[i + j] = w[i - Nk * 4 + j] ^ tmp[j];
    }
}

unsigned char* SubWord(unsigned char* word)
{
    for (int i = 0; i < 4; i++) {
        word[i] = sbox[word[i]];
    }
    return word;
}

unsigned char* RotWord(unsigned char* word)
{
    unsigned char tmp[4];
    memcpy(tmp, word, 4);
    for (int i = 0; i < 4; i++) {
        word[i] = tmp[(i + 1) % 4];
    }
    return word;
}

// Round Ops
void SubBytes(unsigned char state[4][4])
{
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            state[col][row] = sbox[state[col][row]];
        }
    }
}

void InvSubBytes(unsigned char state[4][4])
{
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            state[col][row] = invsbox[state[col][row]];
        }
    }
}

void ShiftRows(unsigned char state[4][4])
{
    unsigned char tmp[4];
    for (int row = 1; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            tmp[col] = state[(row + col) % 4][row];
        }
        for (int col = 0; col < 4; col++) {
            state[col][row] = tmp[col];
        }
    }
}

void InvShiftRows(unsigned char state[4][4])
{
    unsigned char tmp[4];
    for (int row = 1; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            tmp[(row + col) % 4] = state[col][row];
        }
        for (int col = 0; col < 4; col++) {
            state[col][row] = tmp[col];
        }
    }
}

void MixColumns(unsigned char state[4][4])
{
    unsigned char tmp[4];
    unsigned char matmul[][4] = {
            0x02, 0x03, 0x01, 0x01,
            0x01, 0x02, 0x03, 0x01,
            0x01, 0x01, 0x02, 0x03,
            0x03, 0x01, 0x01, 0x02
    };
    for (int col = 0; col < 4; col++) {
        for (int row = 0; row < 4; row++) {
            tmp[row] = state[col][row];
        }
        for (int i = 0; i < 4; i++) {
            state[col][i] = 0x00;
            for (int j = 0; j < 4; j++) {
                state[col][i] ^= mul(matmul[i][j], tmp[j]);
            }
        }
    }
}

void InvMixColumns(unsigned char state[4][4])
{
    unsigned char tmp[4];
    unsigned char matmul[][4] = {
            0x0e, 0x0b, 0x0d, 0x09,
            0x09, 0x0e, 0x0b, 0x0d,
            0x0d, 0x09, 0x0e, 0x0b,
            0x0b, 0x0d, 0x09, 0x0e
    };
    for (int col = 0; col < 4; col++) {
        for (int row = 0; row < 4; row++) {
            tmp[row] = state[col][row];
        }
        for (int i = 0; i < 4; i++) {
            state[col][i] = 0x00;
            for (int j = 0; j < 4; j++) {
                state[col][i] ^= mul(matmul[i][j], tmp[j]);
            }
        }
    }
}

unsigned char mul(unsigned char a, unsigned char b)
{
    unsigned char sb[4];
    unsigned char out = 0;
    sb[0] = b;
    for (int i = 1; i < 4; i++) {
        sb[i] = sb[i - 1] << 1;
        if (sb[i - 1] & 0x80) {
            sb[i] ^= 0x1b;
        }
    }
    for (int i = 0; i < 4; i++) {
        if (a >> i & 0x01) {
            out ^= sb[i];
        }
    }
    return out;
}

void AddRoundKey(unsigned char state[4][4], unsigned char* key)
{
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            state[col][row] ^= key[col * 4 + row];
        }
    }
}
