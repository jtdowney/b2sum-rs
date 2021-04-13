# b2sum-rs

[![CI](https://github.com/jtdowney/b2sum-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/jtdowney/b2sum-rs/actions/workflows/ci.yml)
[![](https://img.shields.io/crates/v/b2sum.svg)](https://crates.io/crates/b2sum)

Rust clone of the BLAKE2b checksum utility in GNU coreutils.

## Install

`cargo install b2sum`

## Usage

```
Print or check BLAKE2 (512-bit) checksums.
With no FILE, or when FILE is -, read standard input.

Usage:
  b2sum [options] [<filename>]...
  b2sum (-h | --help)
  b2sum --version

Options:
  -c, --check           read BLAKE2 sums from the FILEs and check them
  -l, --length=BITS     digest length in bits; must not exceed the maximum for the
                        blake2 algorithm and must be a multiple of 8 [default: 512]
      --tag             create a BSD-style checksum

The following five options are useful only when verifying checksums:
      --ignore-missing  don't fail or report status for missing files
      --quiet           don't print OK for each successfully verified file
      --status          don't output anything, status code shows success
      --strict          exit non-zero for improperly formatted checksum lines
  -w, --warn            warn about improperly formatted checksum lines

  -h, --help            display this help and exit
      --version         output version information and exit

The sums are computed as described in RFC 7693.  When checking, the input
should be a former output of this program.  The default mode is to print
a line with checksum and name for each FILE.
```

## Minimum Supported Rust Version (MSRV)

This crate is guaranteed to compile on stable Rust 1.42 and up. It might compile with older versions but that may change at any time.
