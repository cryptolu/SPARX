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

#ifndef DATA_TYPES_H
#define DATA_TYPES_H

#include "cipher.h"


/*
 *
 * Implementation data types
 *
 */


#if defined(PC) /* PC */

/* Architecture = PC ; Scenario = 0 (cipher operation) */
#if defined(SCENARIO) && (SCENARIO_0 == SCENARIO)



#endif

/* Architecture = PC ; Scenario = 1 */
#if defined(SCENARIO) && (SCENARIO_1 == SCENARIO)



#endif

/* Architecture = PC ; Scenario = 2 */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)



#endif

#endif /* PC */



#if defined(AVR) /* AVR */

/* Architecture = AVR ; Scenario = 0 (cipher operation) */
#if defined(SCENARIO) && (SCENARIO_0 == SCENARIO)



#endif

/* Architecture = AVR ; Scenario = 1 */
#if defined(SCENARIO) && (SCENARIO_1 == SCENARIO)



#endif

/* Architecture = AVR ; Scenario = 2 */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)



#endif

#endif /* AVR */



#if defined(MSP) /* MSP */

/* Architecture = MSP ; Scenario = 0 (cipher operation) */
#if defined(SCENARIO) && (SCENARIO_0 == SCENARIO)



#endif

/* Architecture = MSP ; Scenario = 1 */
#if defined(SCENARIO) && (SCENARIO_1 == SCENARIO)



#endif

/* Architecture = MSP ; Scenario = 2 */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)



#endif

#endif /* MSP */



#if defined(ARM) /* ARM */

/* Architecture = ARM ; Scenario = 0 (cipher operation) */
#if defined(SCENARIO) && (SCENARIO_0 == SCENARIO)



#endif

/* Architecture = ARM ; Scenario = 1 */
#if defined(SCENARIO) && (SCENARIO_1 == SCENARIO)



#endif

/* Architecture = ARM ; Scenario = 2 */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)



#endif

#endif /* ARM */


#endif /* DATA_TYPES_H */
