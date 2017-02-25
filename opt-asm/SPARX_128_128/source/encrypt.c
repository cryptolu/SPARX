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

#include "cipher.h"
#include "constants.h"

#include "round.h"


#if !defined(ARM) && !defined(AVR) && !defined(MSP)

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
    uint8_t i;

    uint16_t *Block = (uint16_t *)block;
    uint16_t *RoundKeys = (uint16_t *)roundKeys;


    for (i = 0; i < NUMBER_OF_ROUNDS; i++)
    {
        round_f(Block, &RoundKeys[32 * i]);
    }


    /* post whitening */
    for (i = 0; i < 8; i ++)
    {
        Block[i] ^= READ_ROUND_KEY_WORD(RoundKeys[32 * NUMBER_OF_ROUNDS + i]);
    }
}

#elif defined(ARM)

/* ARM ASM implementation - begin */

#include "arm_macros.h"

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
    asm volatile(
        /*
            r0 - *block
            r1 - *roundKeys
        */

        /*
            r2 - first branch
            r3 - second branch
            r4 - third branch
            r5 - fourth branch

            r6 - round key / temp
            r7 - temp
            r8 - temp
            r9 - temp

            r10 - halfword mask
            r11 - loop counter
            r12 - loop counter
        */


        /* save context */
        "stmdb sp!, {r2-r12}" "\n\t"


        /* set halfword mask */
        SET_MASK(r10)


        /* load block */
        "ldm r0, {r2-r5}" "\n\t"


        /* initialize loop counter */
        "mov r11, 8" "\n\t"
        "step:" "\n\t"


        /* process first branch */
        /* initialize loop counter */
        "mov r12, 4" "\n\t"
        "b1:" "\n\t"

        ENC_ADD_ROUND_KEY(r2, r6)
        ENC_A(r2, r6, r7, r10)

        /* loop end */
        "subs r12, r12, #1" "\n\t"
        "bne b1" "\n\t"


        /* process second branch */
        /* initialize loop counter */
        "mov r12, 4" "\n\t"
        "b2:" "\n\t"

        ENC_ADD_ROUND_KEY(r3, r6)
        ENC_A(r3, r6, r7, r10)

        /* loop end */
        "subs r12, r12, #1" "\n\t"
        "bne b2" "\n\t"


        /* process third branch */
        /* initialize loop counter */
        "mov r12, 4" "\n\t"
        "b3:" "\n\t"

        ENC_ADD_ROUND_KEY(r4, r6)
        ENC_A(r4, r6, r7, r10)

        /* loop end */
        "subs r12, r12, #1" "\n\t"
        "bne b3" "\n\t"


        /* process fourth branch */
        /* initialize loop counter */
        "mov r12, 4" "\n\t"
        "b4:" "\n\t"

        ENC_ADD_ROUND_KEY(r5, r6)
        ENC_A(r5, r6, r7, r10)

        /* loop end */
        "subs r12, r12, #1" "\n\t"
        "bne b4" "\n\t"


        /* linear layer */
        ENC_L(r2, r3, r4, r5, r6, r7, r8, r9, r10)


        /* loop end */
        "subs r11, r11, #1" "\n\t"
        "bne step" "\n\t"


        /* post whitening */
        ENC_ADD_WHITENING_KEY(r2, r3, r4, r5, r6)


        /* store block */
        "stm r0, {r2-r5}" "\n\t"


        /* restore context */
        "ldmia sp!, {r2-r12}" "\n\t"
    );
}

/* ARM ASM implementation - end */

#elif defined(AVR)

/* AVR ASM implementation - begin */

#include "avr_macros.h"

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
    asm volatile(
        /*
            r25, r24 - *block
            r23, r22 - *roundKeys
        */

        /*
            r7 - first branch
            r8 - first branch
            r9 - first branch
            r10 - first branch

            r11 - second branch
            r12 - second branch
            r13 - second branch
            r14 - second branch

            r15 - third branch
            r16 - third branch
            r17 - third branch
            r18 - third branch

            r19 - fourth branch
            r20 - fourth branch
            r21 - fourth branch
            r22 - fourth branch

            r23 - round key / temp

            r24 - loop counter
            r25 - loop counter
        */


        /* save context */
        "push r7" "\n\t"
        "push r8" "\n\t"
        "push r9" "\n\t"
        "push r10" "\n\t"
        "push r11" "\n\t"
        "push r12" "\n\t"
        "push r13" "\n\t"
        "push r14" "\n\t"
        "push r15" "\n\t"
        "push r16" "\n\t"
        "push r17" "\n\t"


        /* set block pointer: X (r27, r26) */
        "movw r26, r24" "\n\t"
        /* set key pointer: Z (r31, r30) */
        "movw r30, r22" "\n\t"


        /* load block */
        "ld r7, x+" "\n\t"
        "ld r8, x+" "\n\t"
        "ld r9, x+" "\n\t"
        "ld r10, x+" "\n\t"

        "ld r11, x+" "\n\t"
        "ld r12, x+" "\n\t"
        "ld r13, x+" "\n\t"
        "ld r14, x+" "\n\t"

        "ld r15, x+" "\n\t"
        "ld r16, x+" "\n\t"
        "ld r17, x+" "\n\t"
        "ld r18, x+" "\n\t"

        "ld r19, x+" "\n\t"
        "ld r20, x+" "\n\t"
        "ld r21, x+" "\n\t"
        "ld r22, x+" "\n\t"


        /* initialize loop counter */
        "ldi r24, 8" "\n\t"
        "step:" "\n\t"


        /* process first branch */
        /* initialize loop counter */
        "ldi r25, 4" "\n\t"
        "b1:" "\n\t"

        ENC_ADD_ROUND_KEY(r7, r8, r9, r10, r23)
        ENC_A(r7, r8, r9, r10)

        /* loop end */
        "dec r25" "\n\t"
        "brne b1" "\n\t"


        /* process second branch */
        "ldi r25, 4" "\n\t"
        "b2:" "\n\t"

        ENC_ADD_ROUND_KEY(r11, r12, r13, r14, r23)
        ENC_A(r11, r12, r13, r14)

        /* loop end */
        "dec r25" "\n\t"
        "brne b2" "\n\t"


        /* process third branch */
        "ldi r25, 4" "\n\t"
        "b3:" "\n\t"

        ENC_ADD_ROUND_KEY(r15, r16, r17, r18, r23)
        ENC_A(r15, r16, r17, r18)

        /* loop end */
        "dec r25" "\n\t"
        "brne b3" "\n\t"


        /* process fourth branch */
        "ldi r25, 4" "\n\t"
        "b4:" "\n\t"

        ENC_ADD_ROUND_KEY(r19, r20, r21, r22, r23)
        ENC_A(r19, r20, r21, r22)

        /* loop end */
        "dec r25" "\n\t"
        "brne b4" "\n\t"


        /* linear layer */
        ENC_L(r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18, r19, r20, r21, r22, r23)


        /* loop end */
        "dec r24" "\n\t"
        "breq end_step" "\n\t"
        "jmp step" "\n\t"
        "end_step:" "\n\t"


        /* post whitening */
        ENC_ADD_WHITENING_KEY(r7, r8, r9, r10, r23)
        ENC_ADD_WHITENING_KEY(r11, r12, r13, r14, r23)
        ENC_ADD_WHITENING_KEY(r15, r16, r17, r18, r23)
        ENC_ADD_WHITENING_KEY(r19, r20, r21, r22, r23)


        /* store block */
        "st -x, r22" "\n\t"
        "st -x, r21" "\n\t"
        "st -x, r20" "\n\t"
        "st -x, r19" "\n\t"

        "st -x, r18" "\n\t"
        "st -x, r17" "\n\t"
        "st -x, r16" "\n\t"
        "st -x, r15" "\n\t"

        "st -x, r14" "\n\t"
        "st -x, r13" "\n\t"
        "st -x, r12" "\n\t"
        "st -x, r11" "\n\t"

        "st -x, r10" "\n\t"
        "st -x, r9" "\n\t"
        "st -x, r8" "\n\t"
        "st -x, r7" "\n\t"


        /* restore context */
        "pop r17" "\n\t"
        "pop r16" "\n\t"
        "pop r15" "\n\t"
        "pop r14" "\n\t"
        "pop r13" "\n\t"
        "pop r12" "\n\t"
        "pop r11" "\n\t"
        "pop r10" "\n\t"
        "pop r9" "\n\t"
        "pop r8" "\n\t"
        "pop r7" "\n\t"
    );
}

/* AVR ASM implementation - end */

#elif defined(MSP)

/* MSP ASM implementation - begin */

#include "msp_macros.h"

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
    asm volatile(
        /*
            r15 - *block
            r14 - *roundKeys
        */

        /*
            r4 - first branch
            r5 - first branch

            r6 - second branch
            r7 - second branch

            r8 - third branch
            r9 - third branch

            r10 - fourth branch
            r11 - fourth branch

            r12 - round key / temp

            r13 - loop counter
        */


        /* save context */
        "push r4" "\n\t"
        "push r5" "\n\t"
        "push r6" "\n\t"
        "push r7" "\n\t"
        "push r8" "\n\t"
        "push r9" "\n\t"
        "push r10" "\n\t"
        "push r11" "\n\t"


        /* load block */
        "mov @r15+, r4" "\n\t"
        "mov @r15+, r5" "\n\t"
        "mov @r15+, r6" "\n\t"
        "mov @r15+, r7" "\n\t"

        "mov @r15+, r8" "\n\t"
        "mov @r15+, r9" "\n\t"
        "mov @r15+, r10" "\n\t"
        "mov @r15+, r11" "\n\t"


        /* initialize loop counter */
        "mov #8, r13" "\n\t"
        "step:" "\n\t"
        "push r13" "\n\t"


        /* process first branch */
        /* initialize loop counter */
        "mov #4, r13" "\n\t"
        "b1:" "\n\t"

        ENC_ADD_ROUND_KEY(r4, r5, r12)
        ENC_A(r4, r5)

        /* loop end */
        "dec r13" "\n\t"
        "jne b1" "\n\t"


        /* process second branch */
        /* initialize loop counter */
        "mov #4, r13" "\n\t"
        "b2:" "\n\t"

        ENC_ADD_ROUND_KEY(r6, r7, r12)
        ENC_A(r6, r7)

        /* loop end */
        "dec r13" "\n\t"
        "jne b2" "\n\t"


        /* process third branch */
        /* initialize loop counter */
        "mov #4, r13" "\n\t"
        "b3:" "\n\t"

        ENC_ADD_ROUND_KEY(r8, r9, r12)
        ENC_A(r8, r9)

        /* loop end */
        "dec r13" "\n\t"
        "jne b3" "\n\t"


        /* process fourth branch */
        /* initialize loop counter */
        "mov #4, r13" "\n\t"
        "b4:" "\n\t"

        ENC_ADD_ROUND_KEY(r10, r11, r12)
        ENC_A(r10, r11)

        /* loop end */
        "dec r13" "\n\t"
        "jne b4" "\n\t"


        ENC_L(r4, r5, r6, r7, r8, r9, r10, r11, r12)


        /* loop end */
        "pop r13" "\n\t"
        "dec r13" "\n\t"
        "jne step" "\n\t"


        /* post whitening */
        ENC_ADD_WHITENING_KEY(r4, r5, r12)
        ENC_ADD_WHITENING_KEY(r6, r7, r12)
        ENC_ADD_WHITENING_KEY(r8, r9, r12)
        ENC_ADD_WHITENING_KEY(r10, r11, r12)


        /* store block */
        "mov r4, -16(r15)" "\n\t"
        "mov r5, -14(r15)" "\n\t"
        "mov r6, -12(r15)" "\n\t"
        "mov r7, -10(r15)" "\n\t"

        "mov r8, -8(r15)" "\n\t"
        "mov r9, -6(r15)" "\n\t"
        "mov r10, -4(r15)" "\n\t"
        "mov r11, -2(r15)" "\n\t"


        /* restore context */
        "pop r11" "\n\t"
        "pop r10" "\n\t"
        "pop r9" "\n\t"
        "pop r8" "\n\t"
        "pop r7" "\n\t"
        "pop r6" "\n\t"
        "pop r5" "\n\t"
        "pop r4" "\n\t"
    );
}

/* MSP ASM implementation - end */

#endif
