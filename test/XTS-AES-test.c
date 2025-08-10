// Copyright 2023 cryptogus
// reference: https://en.wikipedia.org/wiki/Disk_encryption_theory

#include "aes.h"
#include "XTS-AES-test_vector_wrap.h"
#include <stdio.h>
#include <string.h>


// Function to multiply the tweak value by 2 in GF(2^128)
static void xts_gf_mul(uint8_t *tweak) {
    uint8_t carry = tweak[15] >> 7;
    for (int i = 15; i > 0; i--) {
        tweak[i] = (tweak[i] << 1) | (tweak[i-1] >> 7);
    }
    tweak[0] <<= 1;
    if (carry) tweak[0] ^= 0x87; // 0x87 is the reduction polynomial for GF(2^128), x^128 + x^7 + x^2 + x + 1
}

void xts_aes_enc(void (*aes)(uint8_t*, uint8_t*, uint8_t*), uint8_t *tweak, uint8_t *key1, uint8_t *key2, uint8_t *pt, size_t ptLen, uint8_t *ct)
{
    aes(tweak, tweak, key2);
    
    size_t lastBlockSize = ptLen % 16;
    size_t leftBlockSize;
    if (lastBlockSize == 0) 
    {
        leftBlockSize = 0;
    }
    else
    {
        leftBlockSize = 16 - lastBlockSize;
    }
    for (int j = 0; j < ((ptLen + leftBlockSize)>> 4); j++) // block number
    {
        if (!(ptLen % 16 != 0 && j == ((ptLen + leftBlockSize) >> 4) - 1)) // last block
        {   
            //printf("\nBlock %d: ", j);
            for (int i = 0; i < 16; i++)
            {
                pt[(j*16) + i] ^= tweak[i];
                //printf("%02x ", pt[(j*16) + i]);
            }
            aes(ct + j*16, pt + j*16, key1);

            // XOR the ciphertext with the tweak
            for (size_t i = 0; i < 16; i++) {
                ct[(j*16) + i] ^= tweak[i];
            }
            
            // Update the tweak for the next block
            xts_gf_mul(tweak);
        }
    }
    
    uint8_t pt_tmp[16] = {0,};
    uint8_t ct_tmp[16] = {0,};
    
    if (ptLen % 16 != 0) // last block
     {
        for (size_t i = 0; i < lastBlockSize; i++)
        {
            pt[(ptLen >> 4) * 16 + i] ^= tweak[i];
        }
        memcpy(ct_tmp, ct + ((ptLen >> 4) - 1)* 16, leftBlockSize);
        for (size_t i = 0; i < leftBlockSize; i++)
        {
            ct_tmp[i] ^= tweak[i + lastBlockSize];
        }
        memcpy(pt_tmp, pt + ((ptLen >> 4) * 16), lastBlockSize);
        memcpy(pt_tmp + lastBlockSize, ct_tmp, leftBlockSize);
        aes(ct + ((ptLen >> 4) * 16), pt_tmp, key1);

        // XOR the ciphertext with the tweak
        for (size_t i = 0; i < 16; i++) 
        {
            ct[(ptLen >> 4) * 16 + i] ^= tweak[i];
        }

        memcpy(ct_tmp, ct + (ptLen >> 4) * 16, 16);
        for (size_t i = 0; i < lastBlockSize; i++) 
        {
            ct[(ptLen >> 4) * 16 + i] = ct[((ptLen >> 4) - 1) * 16 + i];
        }
        for (size_t i = 0; i < 16; i++) 
        {
            ct[((ptLen >> 4) - 1) * 16 + i] = ct_tmp[i];
        }
    }
}

// nist test vector
static void xts_aes_enc_test(Aes256Tv *tv)
{
    uint8_t tweak[16] = {0,};
    for (int i = 0; i < ENCRYPT_TEST_COUNT; i++)
    {
        uint8_t ciphertext[128] = {0,};
        xts_aes_enc(AES256_Encrypt, tv[i].iv, tv[i].key, tv[i].key + 32, tv[i].pt, tv[i].ptLen, ciphertext);
        if (memcmp(ciphertext, tv[i].ct, tv[i].ptLen) != 0)
        {
            printf("XTS-AES Encryption test failed at index %d\n", i);
            printf("Expected: ");
            for (int j = 0; j < tv[i].ptLen; j++) {
                printf("%02x", tv[i].ct[j]);
            }
            printf("\nGot:      ");
            for (int j = 0; j < tv[i].ptLen; j++) {
                printf("%02x", ciphertext[j]);
            }
            printf("\n");
            return;
        }
    }
    printf("ALL XTS-AES Encryption test success\n");
}

int main() {
    // Run the XTS-AES encryption test
    xts_aes_enc_test(aesXtsTvEnc);

    return 0;
}