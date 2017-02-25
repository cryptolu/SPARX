/*
 * SPARX source code package
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
#include "rot32.h"
#include "speckey.h"


#if !defined(ARM) && !defined(AVR) && !defined(MSP)

void round_f(uint32_t *left, uint32_t *right, uint32_t *roundKeys)
{
    uint32_t temp;

    uint16_t *b0_l = (uint16_t *)left;
    uint16_t *b0_r = (uint16_t *)left + 1;

    uint16_t *b1_l = (uint16_t *)right;
    uint16_t *b1_r = (uint16_t *)right + 1;


    /* left branch */
    *left ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys[0]);
    speckey(b0_l, b0_r);

    *left ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys[1]);
    speckey(b0_l, b0_r);

    *left ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys[2]);
    speckey(b0_l, b0_r);


    /* right branch */
    *right ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys[3]);
    speckey(b1_l, b1_r);

    *right ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys[4]);
    speckey(b1_l, b1_r);

    *right ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys[5]);
    speckey(b1_l, b1_r);


    /* linear layer */
    temp = *left;
    *right ^= *left ^ rot32l8(*left) ^ rot32r8(*left);
    *left = *right;
    *right = temp;
}

#endif
