<!--
SPDX-FileCopyrightText: 2026 Philip Eklöf

SPDX-License-Identifier: MIT
-->

# yk-piv-age-keygen

This tool can be used to generate keys+certificates in YubiKey PIV that are
compatible with
[age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey). It performs
the same operation that `age-plugin-yubikey --generate` does, but using the
command line rather than via an interactive text menu.

While age-plugin-yubikey is written in rust, yk-piv-age-keygen performs the
very same thing with python, via the libs provided by
[yubikey-manager](https://github.com/Yubico/yubikey-manager).


## Why?

YubiKey 5.7 supports AES management keys, which *should* be used rather than
the older Triple-DES variants. Unfortunately, this support has not landed in
age-plugin-yubikey yet ([issue
#92](https://github.com/str4d/age-plugin-yubikey/issues/92)), meaning that you
currently can't generate keys with `age-plugin-yubikey` if your YubiKey is
configured using an AES management key. For now, `yk-piv-age-keygen` fills that
gap.

There's some other non-closed issues with YubiKey 5.7 at this time, as well.
Combining `yk-piv-age-keygen` with my tiny
[age-plugin-yubikey-57](https://github.com/phiekl/age-plugin-yubikey-57) fork
simply makes age-plugin-yubikey usable with YubiKey >=5.7.

**Hence, this project is pointless and obsolete as soon as those issuses are
fixed.** Instead, it can be seen as an example on how to use the ykman/yubikit
libs, at least for PIV operations.

## Installation

The script has been developed for use on Debian 13. Setting
[cli.py](src/yk_piv_age_keygen/cli.py) executable, it should run just fine
given that the `yubikey-manager` deb package is installed.

If you're not on Debian 13, use [uv](https://github.com/astral-sh/uv) and run
`uv run yk-piv-age-keygen --help` (in the repo root), which should generate a
venv for you with a fully working set of dependencies to execute the command.

Just make sure that pcscd.service is running. If `ykman piv info` works, so
should this.

## Usage

```
$ yk-piv-age-keygen --help
usage: yk-piv-age-keygen [-h] [-v] [-q] [-S <num>] -s {1..20} [-p <pin>]
                         [-m <key>] [-P {never,once,always}]
                         [-T {never,always,cached}] [--force]

options:
  -h, --help            show this help message and exit
  -v, --verbose         increase the verbosity level
  -q, --quiet           decrease log level to WARNING
  -S, --serial <num>    use the YubiKey with this serial (required with
                        multiple devices)
  -s, --slot {1..20}    generate a key and certificate in this retired slot
  -p, --pin <pin>       PIN code (requested interactively if not specified)
  -m, --mgmt-key <key>  management key (required if key is not PIN
                        derived/protected)
  -P, --pin-policy {never,once,always}
                        new PIN policy for slot (default: once)
  -T, --touch-policy {never,always,cached}
                        new touch policy for slot (default: always)
  --force               force replacement of currently existing
                        key/certificate in slot
```

## Example

Generate a new key+certificate in the reserved slot #20:
```
$ yk-piv-age-keygen -s 20
INFO: Found YubiKey with serial '12345678'.
INFO: No existing certificate found in PIV slot 95 (RETIRED20).
Enter PIN for YubiKey with serial '12345678' (default: 123456):
INFO: Management key fetched from data protected by PIN.
INFO: Authenticating ...
Touch your YubiKey...
INFO: Successfully authenticated.
INFO: Generating ECCP256 key in slot 95 (RETIRED20) ...
INFO: Private key generated in slot 95 (RETIRED20) of type ECCP256
INFO: Generating certificate ...
Touch your YubiKey...
INFO: Data written to object slot 0x5fc120
INFO: Certificate written to slot 95 (RETIRED20), compression=False
INFO: Data written to object slot 0x5fc102
```

... which would make it show up like this:

```
$ ykman piv info
PIV version:              5.7.1
PIN tries remaining:      3/3
PUK tries remaining:      3/3
Management key algorithm: AES192
Management key is stored on the YubiKey, protected by PIN.
CHUID: d0c674ab66d02f0c09f555ac70216de537490f910da2088cd46933d6775d56781a71f152211a12b104cc8d471884bed16289af118daad8c7ab3d6d
CCC:   No data available
Slot 95 (RETIRED20):
  Private key type: ECCP256
  Public key type:  ECCP256
  Subject DN:       CN=age identity ba46c6ba,OU=0.5.0,O=age-plugin-yubikey
  Issuer DN:        CN=age identity ba46c6ba,OU=0.5.0,O=age-plugin-yubikey
  Serial:           b0:38:a5:3e:c9:21:6d:5f:f0:bd:c8:7e:f3:90:42:8c:20:9a:35:c3
  Fingerprint:      90fe04ee14d13ab94c68e23a79f508733f926dd39f0dfce3f85adc213a519f1e
  Not before:       2026-01-20T23:29:09+00:00
  Not after:        9999-12-31T23:59:59+00:00
```

... and gets recognized by `age-plugin-yubikey` itself:
```
$ age-plugin-yubikey --list
#       Serial: 12345678, Slot: 20
#         Name: age identity ba46c6ba
#      Created: Tue, 20 Jan 2026 23:29:09 +0000
#   PIN policy: Once   (A PIN is required once per session, if set)
# Touch policy: Always (A physical touch is required for every decryption)
age1yubikey1qv0s8amuj04jhdjz0nkadeurekd5xyqrhxt9xksd09d0jca424sau5pvfum
```

Just FYI, it won't overwrite populated slots unless `--force` is used:
```
$ yk-piv-age-keygen -s 20
INFO: Found YubiKey with serial '12345678'.
ERROR: PIV slot 95 (RETIRED20) already contains a key+certificate.
```
