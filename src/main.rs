#![recursion_limit = "1024"]

extern crate blake2b_simd;
#[macro_use]
extern crate error_chain;
extern crate rustc_serialize;
extern crate docopt;

mod errors {
    error_chain! {
        foreign_links {
            Fmt(::std::fmt::Error);
            Io(::std::io::Error);
        }
    }
}

use docopt::Docopt;
use errors::*;
use std::fmt::Write;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;
use std::process;

const BUFFER_SIZE: usize = 8 * 1024;
const USAGE: &'static str = "
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
";

#[derive(Debug, RustcDecodable)]
struct Args {
    arg_filename: Vec<String>,
    flag_check: bool,
    flag_ignore_missing: bool,
    flag_length: usize,
    flag_quiet: bool,
    flag_status: bool,
    flag_strict: bool,
    flag_tag: bool,
    flag_version: bool,
    flag_warn: bool,
}

fn print_version() -> ! {
    let version = env!("CARGO_PKG_VERSION");
    println!("b2sum-rs {}", version);
    process::exit(0)
}

fn hash_reader<R: Read>(length: usize, mut reader: R) -> Result<String> {
    let mut digest = blake2b_simd::Params::new().hash_length(length).to_state();
    let mut buffer = [0; BUFFER_SIZE];

    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(c) => {
                digest.update(&buffer[..c]);
            }
            Err(e) => bail!(e),
        }
    }

    let output = digest.finalize();
    let mut result = String::with_capacity(length * 2);
    for &b in output.as_bytes() {
        write!(&mut result, "{:x}", b)?;
    }

    Ok(result)
}

fn hash_file<P: AsRef<Path>>(length: usize, path: P) -> Result<String> {
    let file = File::open(path)?;
    hash_reader(length, file)
}

fn split_check_line(line: &str) -> Result<(&str, &str)> {
    let hash_length = line.chars()
        .position(|c| !c.is_digit(16))
        .unwrap_or(0);
    if hash_length < 2 || hash_length % 2 != 0 || hash_length > 128 {
        bail!("Invalid hash length: {}", hash_length);
    }

    let hash = &line[0..hash_length];
    let line = &line[hash_length..];
    if line.len() < 3 {
        bail!("Malformed line");
    }

    let filename = &line[2..];

    Ok((hash, filename))
}

fn check_input<R: BufRead>(args: &Args, check_filename: &str, reader: R) -> Result<bool> {
    let print_result = !(args.flag_quiet || args.flag_status);
    let mut errors = false;

    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }

        let (hash, filename) = match split_check_line(line) {
            Ok((hash, filename)) => (hash, filename),
            Err(e) => {
                if args.flag_strict {
                    errors = true;
                }

                if args.flag_warn {
                    println!("{}:{}: {}", check_filename, i + 1, e.description())
                }

                continue;
            }
        };

        let length = hash.len() / 2;
        let calculated_hash = match hash_file(length, filename) {
            Ok(h) => h,
            Err(Error(ErrorKind::Io(ref e), _)) if e.kind() == io::ErrorKind::NotFound && args.flag_ignore_missing => continue,
            Err(e) => {
                errors = true;
                if !args.flag_status {
                    println!("{}: FAILED {}", filename, e.description());
                }

                continue;
            }
        };

        let matched = hash == calculated_hash;
        if !matched {
            errors = true;
        }

        if print_result {
            print!("{}: ", filename);
            if matched {
                println!("OK");
            } else {
                println!("FAILED");

            }
        }
    }

    Ok(errors)
}

fn check_args(args: Args) -> Result<i32> {
    let filename = args.arg_filename[0].as_str();
    let errors = if filename == "-" {
        let stdin = io::stdin();
        let reader = stdin.lock();
        check_input(&args, filename, reader)?
    } else {
        let file = File::open(filename)?;
        let reader = BufReader::new(file);
        check_input(&args, filename, reader)?
    };

    let code = if errors { 1 } else { 0 };
    Ok(code)
}

fn hash_args(args: Args) -> Result<i32> {
    let length = args.flag_length / 8;
    for filename in args.arg_filename {
        let hash = if filename == "-" {
            let stdin = io::stdin();
            hash_reader(length, stdin)?
        } else {
            hash_file(length, &filename)?
        };

        if args.flag_tag {
            print!("BLAKE2b");
            if args.flag_length < 512 {
                print!("-{}", args.flag_length);
            }

            println!(" ({}) = {}", filename, hash);
        } else {
            println!("{}  {}", hash, filename);
        }
    }

    Ok(0)
}

quick_main!(run);

fn run() -> Result<i32> {
    let mut args: Args = Docopt::new(USAGE)
        .and_then(|d| d.decode())
        .unwrap_or_else(|e| e.exit());

    if args.flag_version {
        print_version();
    }

    if args.arg_filename.is_empty() {
        args.arg_filename.push("-".to_string());
    }

    if args.flag_check {
        check_args(args)
    } else {
        hash_args(args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_check_line_with_valid_line() {
        let line = "c0ae24f806df19d850565b234bc37afd5035e7536388290db9413c98578394313f38b093143ecfbc208425d54b9bfef0d9917a9e93910f7914a97e73fea23534  test";
        let (hash, filename) = split_check_line(line).unwrap();
        assert_eq!("c0ae24f806df19d850565b234bc37afd5035e7536388290db9413c98578394313f38b093143ecfbc208425d54b9bfef0d9917a9e93910f7914a97e73fea23534",
                   hash);
        assert_eq!("test", filename);
    }

    #[test]
    fn split_check_line_with_truncated_line() {
        let line = "c0ae24f806df19d850565b234bc37afd5035e7536388290db9413c98578394313f38b093143ecfbc208425d54b9bfef0d9917a9e93910f7914a97e73fea23534 ";
        let result = split_check_line(line).unwrap_err();
        assert_eq!("Malformed line", result.description());
    }

    #[test]
    fn split_check_line_with_missing_filename() {
        let line = "c0ae24f806df19d850565b234bc37afd5035e7536388290db9413c98578394313f38b093143ecfbc208425d54b9bfef0d9917a9e93910f7914a97e73fea23534  ";
        let result = split_check_line(line).unwrap_err();
        assert_eq!("Malformed line", result.description());
    }

    #[test]
    fn split_check_line_with_too_small_hash() {
        let line = "c  test";
        let result = split_check_line(line).unwrap_err();
        assert_eq!("Invalid hash length: 1", result.description());
    }

    #[test]
    fn split_check_line_with_too_long_hash() {
        let line = "c0ae24f806df19d850565b234bc37afd5035e7536388290db9413c98578394313f38b093143ecfbc208425d54b9bfef0d9917a9e93910f7914a97e73fea2353400  test";
        let result = split_check_line(line).unwrap_err();
        assert_eq!("Invalid hash length: 130", result.description());
    }

    #[test]
    fn split_check_line_with_non_even_hash() {
        let line = "c0ae0  test";
        let result = split_check_line(line).unwrap_err();
        assert_eq!("Invalid hash length: 5", result.description());
    }
}
