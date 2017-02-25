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

#include "round.h"
#include "cipher.h"
#include "rot16.h"
#include "rot32.h"
#include "speckey.h"


#if !defined(ARM) && !defined(AVR) && !defined(MSP)

void round_f(uint16_t *block, uint16_t *roundKeys)
{
    uint16_t temp;


    /* first branch */
    block[0] ^= READ_ROUND_KEY_WORD(roundKeys[0]);
    block[1] ^= READ_ROUND_KEY_WORD(roundKeys[1]);
    speckey(&block[0], &block[1]);

    block[0] ^= READ_ROUND_KEY_WORD(roundKeys[2]);
    block[1] ^= READ_ROUND_KEY_WORD(roundKeys[3]);
    speckey(&block[0], &block[1]);

    block[0] ^= READ_ROUND_KEY_WORD(roundKeys[4]);
    block[1] ^= READ_ROUND_KEY_WORD(roundKeys[5]);
    speckey(&block[0], &block[1]);

    block[0] ^= READ_ROUND_KEY_WORD(roundKeys[6]);
    block[1] ^= READ_ROUND_KEY_WORD(roundKeys[7]);
    speckey(&block[0], &block[1]);


    /* second branch */
    block[2] ^= READ_ROUND_KEY_WORD(roundKeys[8]);
    block[3] ^= READ_ROUND_KEY_WORD(roundKeys[9]);
    speckey(&block[2], &block[3]);

    block[2] ^= READ_ROUND_KEY_WORD(roundKeys[10]);
    block[3] ^= READ_ROUND_KEY_WORD(roundKeys[11]);
    speckey(&block[2], &block[3]);

    block[2] ^= READ_ROUND_KEY_WORD(roundKeys[12]);
    block[3] ^= READ_ROUND_KEY_WORD(roundKeys[13]);
    speckey(&block[2], &block[3]);

    block[2] ^= READ_ROUND_KEY_WORD(roundKeys[14]);
    block[3] ^= READ_ROUND_KEY_WORD(roundKeys[15]);
    speckey(&block[2], &block[3]);


    /* third branch */
    block[4] ^= READ_ROUND_KEY_WORD(roundKeys[16]);
    block[5] ^= READ_ROUND_KEY_WORD(roundKeys[17]);
    speckey(&block[4], &block[5]);

    block[4] ^= READ_ROUND_KEY_WORD(roundKeys[18]);
    block[5] ^= READ_ROUND_KEY_WORD(roundKeys[19]);
    speckey(&block[4], &block[5]);

    block[4] ^= READ_ROUND_KEY_WORD(roundKeys[20]);
    block[5] ^= READ_ROUND_KEY_WORD(roundKeys[21]);
    speckey(&block[4], &block[5]);

    block[4] ^= READ_ROUND_KEY_WORD(roundKeys[22]);
    block[5] ^= READ_ROUND_KEY_WORD(roundKeys[23]);
    speckey(&block[4], &block[5]);


    /* fourth branch */
    block[6] ^= READ_ROUND_KEY_WORD(roundKeys[24]);
    block[7] ^= READ_ROUND_KEY_WORD(roundKeys[25]);
    speckey(&block[6], &block[7]);

    block[6] ^= READ_ROUND_KEY_WORD(roundKeys[26]);
    block[7] ^= READ_ROUND_KEY_WORD(roundKeys[27]);
    speckey(&block[6], &block[7]);

    block[6] ^= READ_ROUND_KEY_WORD(roundKeys[28]);
    block[7] ^= READ_ROUND_KEY_WORD(roundKeys[29]);
    speckey(&block[6], &block[7]);

    block[6] ^= READ_ROUND_KEY_WORD(roundKeys[30]);
    block[7] ^= READ_ROUND_KEY_WORD(roundKeys[31]);
    speckey(&block[6], &block[7]);


    /* linear layer */
    uint32_t *Block = (uint32_t *)block;
    uint32_t t = Block[0] ^ Block[1];
    uint32_t tx[2];

    tx[0] = Block[0];
    tx[1] = Block[1];

    t = rot32l8(t) ^ rot32r8(t);
    Block[0] ^= t;
    Block[1] ^= t;

    t = Block[0];
    Block[0] = (Block[0] & 0xffff0000) | (Block[1] & 0x0000ffff);
    Block[1] = (Block[1] & 0xffff0000) | (t & 0x0000ffff);

    Block[0] ^= Block[2];
    Block[1] ^= Block[3];

    Block[2] = tx[0];
    Block[3] = tx[1];
}

#endif
