# Why v1.0.3 could not be rebuilt — 2026-09-08

The published v1.0.3 image and an independent rebuild of the same commit
disagreed. This is the evidence behind the story told under
[Reproducibility](../README.md#reproducibility); read that first for what the
two defects were and how they are fixed. What is here is the measurement.

It was not a Secure Boot signature mismatch: both disk images carry an unsigned
`bootx64.efi` identical to their own `bzImage`.

## The measurement

Source `772980f`; Buildroot `2026.02.3`; Linux `6.19.14`. Both kernels report
`buildroot@buildroot`, build number 1, and the same
`SOURCE_DATE_EPOCH=1781643700`.

| Artifact | Downloaded release | Local rebuild |
| --- | --- | --- |
| `bzImage` | `0328ef6507701310f686c54d08b9a485e8bb37d8cb67fa701f29f67e09e313c6` | `06ae43730957aa6a41d1ecce33920b6fd65ab9bcfeac7502a3689e1eeba286d0` |
| `signeros-1.0.3-x86_64.img` | `d2700a84eadf10ec9a1e9f241c4a8b885e9efb9a2285d1efe2917d1b25b20cfe` | `cb362d6cf37818fb9cc2b3bf9ecdf0e2e432ec9110a165f3041a154da7e09a7c` |

Decompressing both XZ payloads and parsing the embedded `newc` archives gives
445 entries each. Every name and every piece of cpio metadata agrees. Four file
*contents* differ, and nothing else does — outside the initramfs the two kernels
differ only in the 20-byte GNU build ID, which follows the payload:

```
usr/bin/pcre2grep
usr/bin/pcre2test
usr/lib/libpcre2-posix.so.3.0.7
usr/lib/libstdc++.so.6.0.33
```

## PCRE2: the erased RPATH keeps its length

Libtool links these three with an absolute build-directory `RPATH`, and
Buildroot's `support/scripts/fix-rpath` has patchelf sanitise it. Patchelf
overwrites the string with `X` bytes and **preserves its length**, so the
dependent offsets and relocations keep the original layout:

- `libpcre2-posix.so.3.0.7`: 61 placeholder bytes in the release, 65 locally.
- `pcre2grep`: `DT_STRSZ=1240` in the release, `1244` locally.

The path scan in guardrail 4b passes on both, correctly — the path really is
gone. What survives is how many characters it was.

**Causal proof.** Rebuilding the *old* recipe in a directory four characters
shorter than the original local one, then applying Buildroot's RPATH
sanitisation and strip options, reproduces all three release files byte for
byte. Rebuilds in two directories of different lengths disagree with each other
under the old recipe and agree under the new one.

**Fix.** `PCRE2_POST_CONFIGURE_HOOKS` in `external.mk` clears
`hardcode_libdir_flag_spec` and disables libtool's `LD_RUN_PATH` mechanism, so
no `RPATH` is written at link time. Both halves are needed: clearing only the
first fixes the two executables and leaves the library path-dependent. Beyond
that, `post-build.sh` now deletes `pcre2grep`, `pcre2test`, `libpcre2-8` and
`libpcre2-posix` from the image — only `libpcre2-16` is linked, by `libQt5Core`,
and the rest was 714 KiB of resident RAM nothing referenced. Three of these four
files are therefore no longer on the image at all.

## libstdc++: the build host's msgfmt

`GLIBCXX_ENABLE_CLOCALE` in GCC's `libstdc++-v3/acinclude.m4` enables NLS by
default and probes the build host for `msgfmt`; with one present, the library
uses gettext for exception messages. The release library imports `gettext` and
the original local one does not. `BR2_SYSTEM_ENABLE_NLS` was already off, but
`package/gcc/gcc-final/gcc-final.mk` runs its own configure command, which never
received the generic host-autotools `--disable-nls`.

**Causal proof.** Recompiling the NLS-dependent libstdc++ objects with
`_GLIBCXX_USE_NLS=1`, regenerating the affected assembly and relinking produces
the release library exactly, after the normal strip:
`f9f547d993d0f972db80953302abfd42b75cf54cf031c849f6bd5d56825c6b0c`.

**Fix.** `BR2_EXTRA_GCC_CONFIG_OPTIONS="--disable-nls"` in the defconfig. The
check that matters is on a host that *has* `msgfmt`, which is the only kind that
could show the defect: `build/<triplet>/libstdc++-v3/config.log` then records
`found /usr/bin/msgfmt` and `USE_NLS='no'` in the same run, and `config.h`
leaves `_GLIBCXX_USE_NLS` undefined.

## Not the disk-image wrapper

Reassembling the *downloaded* `bzImage` with this repository's post-image script,
the existing host tools, `SOURCE_DATE_EPOCH=1781643700`, `TZ=UTC` and `LC_ALL=C`
reproduces the downloaded image's complete SHA-256
(`d2700a84eadf10ec9a1e9f241c4a8b885e9efb9a2285d1efe2917d1b25b20cfe`). So no
wrapper defect is needed to explain the pair; the 2026-09-06 `--invariant` fix
holds. The UTC environment matters only when invoking post-image by hand.

## What the guardrail covers, and why it reads BUILD_DIR

Editing the defconfig does not rebuild a cached toolchain, and re-running a
build does not reconfigure an already-configured package. A stale package is
therefore the one way these defects travel forward, and it is a state no
configuration file admits to. `post-build.sh` checks the *generated* libtool
script PCRE2 was configured with and the *generated* `config.h` libstdc++ was
built with, and fails with the command that fixes it.

## What this does not establish

- **No second host.** Every corrected artifact was built here. The fixes are
  validated by cross-directory package rebuilds and by forcing the `msgfmt`
  probe both ways, not by another machine's number.
- **No from-scratch toolchain during the investigation.** The corrected local
  build reused a toolchain whose libstdc++ already had NLS disabled; PCRE2 was
  rebuilt from scratch.
- **The forensic outputs were not kept.** The experiment logs lived in
  `/tmp/signeros-repro/` on the investigated host and are gone. Every number
  quoted above is reproducible from the recipe described; none of it is
  inspectable after the fact.

## The release numbers are not in this file

The corrected recipe produces a different payload by construction, and the
version string is stamped into `/etc/signeros-build` inside the initramfs, so
the hashes measured during this investigation are neither the v1.0.3 assets'
nor v1.0.4's. The numbers to compare against are the ones published with the
**v1.0.4** release.
