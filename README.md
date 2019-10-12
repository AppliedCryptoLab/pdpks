# pdpks
The implementation of the Key-Insulated and Privacy-Preserving Signature Scheme with Publicly Derived Public Key.

# Installation Requirements

## Environment

* system requirements : Linux
* headers included from C standard library: `stdint.h`, `assert.h`, `string.h`, `stdio.h`, `sys/types.h`, `errno.h`, `sys/stat.h`, `fcntl.h`, `inttypes.h`, `stddef.h`, `stdlib.h`, `stdbool.h`.
* headers included from Linux standard library: `unistd.h`, `sys/syscall.h`.

## Build and Test
To download, build and run `PDPKS_test.cpp` in PDPKS, follow the following steps:

```
git clone git://github.com/herumi/mcl
cd mcl
git clone git://github.com/AppliedCryptoLab/pdpks
mv pdpks/src/PDPKS .
mv pdpks/Makefile .
make PDPKS
./bin/PDPKS.exe
``` 

## Other tests
To compare with PDPKS, we also provide a test for ECDSA.
To run `ecdsa.cpp` in ECDSA, stay in directory `mcl` and continue to follow the following steps: 
```
mv pdpks/src/ECDSA .
make ECDSA
./bin/ECDSA.exe
``` 


# Details of Test

## Test of PDPKS

The elliptic curve we choose for PDPKS is a BN curve with parameter u = 2^114 + 2^101 − 2^14 − 1.

`PDPKS_test.cpp` tests:
* the correctness of the whole scheme by running each function in order
* average and median runtime of 100 times of `RandZpGen()` . It generates random elements in Zp*.
* average and median runtime of 100 times of `Setup()`.
* average and median runtime of 100 times of `MasterKeyGen()` which is used to generate MPK, MSVK and MSSK.
* average and median runtime of 100 times of `VrfyKeyDerive()` which is used to generate DVK.
* average and median runtime of 100 times of `VrfyKeyCheck()` unless some checks fail and failures are reported.
* average and median runtime of 100 times of `SignKeyDrv()`which is used to generate DSK.
* average and median runtime of 100 times of `Sign()` which outputs a signature for a message
* average and median runtime of 100 times of `Verify()`unless a signature is invalid.

In addition, `PDPKS_test.cpp` outputs serialized byte size of essential parameters, keys and signature in PDPKS.

## Test of ECDSA

The curve we choose for ECDSA test is secp256k1. 

`ECDSA.cpp` tests:
* the correctness of the whole scheme
* average and median runtime of 100 times of `Sign()` which outputs a signature of a message
* average and median runtime of 100 times of `Verify()`unless a signature is invalid.


# Introduction of Source Files

## Files in PDPKS
* `PDPKS.h`: the implementation of all used function in our PDPKS
* `cpucycles.h`: functions used to record cpucycles
* `speed.h`: functions used to calculate the speed
* `PDPKS_test.cpp`: test of main functions in `PDPKS.h`

## Files in ECDSA
* `cpucycles.h`: functions used to record cpucycles
* `speed.h`: functions used to calculate the speed
* `ecdsa.cpp`: test of ecdsa

# MCL copyright
Our implementation is based on MCL library at https://github.com/herumi/mcl by MITSUNARI Shigeo.

According to the 3-Clause BSD License , here we retain the original copyright notice.

The copyright file `COPYRIGHT_MCL` is attached.
