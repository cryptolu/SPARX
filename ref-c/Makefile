#
# SPARX source code package
#
# Copyright (C) 2016, 2017 CryptoLUX (https://www.cryptolux.org)
#
# Written by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
#
# You may use this work under the terms of a Creative Commons CC0 1.0
# License/Waiver or the Apache Public License 2.0, at your option. The terms of
# these licenses can be found at:
#
# - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
# - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
#
# You should have received a copy of both of these licenses along with this
# software. If not, they may be obtained at the above URLs.
#

# SPARX instances
SPARX_64_128 = 0
SPARX_128_128 = 1
SPARX_128_256 = 2

CFLAGS += -Werror

SRC = sparx.c

.PHONY: all test clean

all: clean
	$(CC) $(CFLAGS) $(SRC) -o sparx_64_128  -DSPARX_INSTANCE=$(SPARX_64_128)
	$(CC) $(CFLAGS) $(SRC) -o sparx_128_128 -DSPARX_INSTANCE=$(SPARX_128_128)
	$(CC) $(CFLAGS) $(SRC) -o sparx_128_256 -DSPARX_INSTANCE=$(SPARX_128_256)

test:
	./sparx_64_128
	./sparx_128_128
	./sparx_128_256

clean:
	rm -rf sparx_64_128 sparx_128_128 sparx_128_256
	rm -rf *~
