# SPARX

The SPARX source code package includes various implementation of SPARX, 
a family of lightweight block ciphers.

The [SPARX webpage](https://www.cryptolux.org/index.php/SPARX) gives links to 
detailed specs, design rationale, security proofs, and many more.

## Resources

In the repository you will find the following directories:

Directory | Description
----------|---------------------------------------------------------------------
`ref-c`   | Reference C implementation
`opt-asm` | Optimized assembly implementations for AVR, MSP and ARM

## Usage

### Reference implementations
[![Build Status](https://travis-ci.org/cryptolu/SPARX.svg?branch=master)](https://travis-ci.org/cryptolu/SPARX)
[![Build status](https://ci.appveyor.com/api/projects/status/g7ol0icxdeq2er2b?svg=true)](https://ci.appveyor.com/project/cryptolu/SPARX)

Run `make` in `ref-c` directory to build the executables `sparx_64_128`, 
`sparx_128_128` and `sparx_64_256`. Run `make test` to verify that your build 
produces valid results.

### Optimized implementations
The optimized assembly implementations are designed to work with the
[FELICS framework](https://www.cryptolux.org/index.php/FELICS). 
See [FELICS](https://www.cryptolux.org/index.php/FELICS) for details 
on how to use them.

## Benchmarks

For detailed benchmarks on embedded platforms see 
[FELICS](https://www.cryptolux.org/index.php/FELICS).

## License

The SPARX code in this repository is copyright (c) 2016, 2017 
[CryptoLUX](https://www.cryptolux.org), and dual licensed under the
[CC0 License](https://creativecommons.org/about/cc0) and the
[Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0). For more info
see the [`LICENSE`](LICENSE) file.

All licenses are therefore [GPL-compatible](https://www.gnu.org/licenses/license-list.en.html#GPLCompatibleLicenses).

## Acknowledgement
This work is supported by the CORE project ACRYPT (ID C12-15-4009992) funded by 
the [Fonds National de la Recherche, Luxembourg](https://www.fnr.lu/).
