/*
 * SPARX reference source code package
 *
 * Copyright (C) 2016, 2017 CryptoLUX (https://www.cryptolux.org)
 *
 * Written by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
 *
 * You may use this work under the terms of a Creative Commons CC0 1.0 
 * License/Waiver or the Apache Public License 2.0, at your option. The terms of
 * these licenses can be found at:
 *
 * - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
 * - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of both of these licenses along with this
 * software. If not, they may be obtained at the above URLs.
 */

#include <stdint.h>

#include "round_inverse.h"
#include "cipher.h"
#include "rot16.h"
#include "rot32.h"
#include "speckey_inverse.h"


#if !defined(ARM) && !defined(AVR) && !defined(MSP)

void round_f_inverse(uint16_t *block, uint16_t *roundKeys)
{
    uint16_t temp;


    /* linear layer */
    uint32_t *Block = (uint32_t *)block;
    uint32_t t = Block[2] ^ Block[3];
    uint32_t tx[2];

    tx[0] = Block[2];
    tx[1] = Block[3];

    t = rot32l8(t) ^ rot32r8(t);
    Block[2] ^= t;
    Block[3] ^= t;

    t = Block[2];
    Block[2] = (Block[2] & 0xffff0000) | (Block[3] & 0x0000ffff);
    Block[3] = (Block[3] & 0xffff0000) | (t & 0x0000ffff);

    Block[2] ^= Block[0];
    Block[3] ^= Block[1];

    Block[0] = tx[0];
    Block[1] = tx[1];


    /* fourth branch */
    speckey_inverse(&block[6], &block[7]);
    block[7] ^= READ_ROUND_KEY_WORD(roundKeys[31]);
    block[6] ^= READ_ROUND_KEY_WORD(roundKeys[30]);

    speckey_inverse(&block[6], &block[7]);
    block[7] ^= READ_ROUND_KEY_WORD(roundKeys[29]);
    block[6] ^= READ_ROUND_KEY_WORD(roundKeys[28]);

    speckey_inverse(&block[6], &block[7]);
    block[7] ^= READ_ROUND_KEY_WORD(roundKeys[27]);
    block[6] ^= READ_ROUND_KEY_WORD(roundKeys[26]);

    speckey_inverse(&block[6], &block[7]);
    block[7] ^= READ_ROUND_KEY_WORD(roundKeys[25]);
    block[6] ^= READ_ROUND_KEY_WORD(roundKeys[24]);


    /* third branch */
    speckey_inverse(&block[4], &block[5]);
    block[5] ^= READ_ROUND_KEY_WORD(roundKeys[23]);
    block[4] ^= READ_ROUND_KEY_WORD(roundKeys[22]);

    speckey_inverse(&block[4], &block[5]);
    block[5] ^= READ_ROUND_KEY_WORD(roundKeys[21]);
    block[4] ^= READ_ROUND_KEY_WORD(roundKeys[20]);

    speckey_inverse(&block[4], &block[5]);
    block[5] ^= READ_ROUND_KEY_WORD(roundKeys[19]);
    block[4] ^= READ_ROUND_KEY_WORD(roundKeys[18]);

    speckey_inverse(&block[4], &block[5]);
    block[5] ^= READ_ROUND_KEY_WORD(roundKeys[17]);
    block[4] ^= READ_ROUND_KEY_WORD(roundKeys[16]);


    /* second branch */
    speckey_inverse(&block[2], &block[3]);
    block[3] ^= READ_ROUND_KEY_WORD(roundKeys[15]);
    block[2] ^= READ_ROUND_KEY_WORD(roundKeys[14]);

    speckey_inverse(&block[2], &block[3]);
    block[3] ^= READ_ROUND_KEY_WORD(roundKeys[13]);
    block[2] ^= READ_ROUND_KEY_WORD(roundKeys[12]);

    speckey_inverse(&block[2], &block[3]);
    block[3] ^= READ_ROUND_KEY_WORD(roundKeys[11]);
    block[2] ^= READ_ROUND_KEY_WORD(roundKeys[10]);

    speckey_inverse(&block[2], &block[3]);
    block[3] ^= READ_ROUND_KEY_WORD(roundKeys[9]);
    block[2] ^= READ_ROUND_KEY_WORD(roundKeys[8]);


    /* first branch */
    speckey_inverse(&block[0], &block[1]);
    block[1] ^= READ_ROUND_KEY_WORD(roundKeys[7]);
    block[0] ^= READ_ROUND_KEY_WORD(roundKeys[6]);

    speckey_inverse(&block[0], &block[1]);
    block[1] ^= READ_ROUND_KEY_WORD(roundKeys[5]);
    block[0] ^= READ_ROUND_KEY_WORD(roundKeys[4]);

    speckey_inverse(&block[0], &block[1]);
    block[1] ^= READ_ROUND_KEY_WORD(roundKeys[3]);
    block[0] ^= READ_ROUND_KEY_WORD(roundKeys[2]);

    speckey_inverse(&block[0], &block[1]);
    block[1] ^= READ_ROUND_KEY_WORD(roundKeys[1]);
    block[0] ^= READ_ROUND_KEY_WORD(roundKeys[0]);
}

#endif
