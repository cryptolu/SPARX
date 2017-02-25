/*
 * SPARX source code package
 *
 * Copyright (C) 2017 CryptoLUX (https://www.cryptolux.org)
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

/* Stringification on variadic macro arguments to enable inline ASM macros. 
 * ... Heavily inspired from:
 * 1. stringify.h in FELICS (https://www.cryptolux.org/index.php/FELICS)
 * 2. http://stackoverflow.com/a/20384872
 * 3. http://stackoverflow.com/a/5957810
 * 4. https://gcc.gnu.org/onlinedocs/cpp/Variadic-Macros.html
 */
#define TO_STR_(args...) #args
#define STR(args...) TO_STR_(args)
