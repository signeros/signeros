# v1.0.3 reproducibility investigation — 2026-09-08

The downloaded v1.0.3 release and the independent local build differ because of
**two build defects affecting four files in the initramfs**. This is not a Secure
Boot signature mismatch. Both disk images contain an unsigned `bootx64.efi`
identical to their accompanying `bzImage`.

## Original evidence

Source checkout: `772980f`; Buildroot: unmodified `2026.02.3`; Linux: `6.19.14`.
Both kernels report `buildroot@buildroot`, build number 1 and the same timestamp
(`SOURCE_DATE_EPOCH=1781643700`, 2026-06-16 21:01:40 UTC).

| Artifact | Downloaded release SHA-256 | Original local SHA-256 |
| --- | --- | --- |
| `bzImage` | `0328ef6507701310f686c54d08b9a485e8bb37d8cb67fa701f29f67e09e313c6` | `06ae43730957aa6a41d1ecce33920b6fd65ab9bcfeac7502a3689e1eeba286d0` |
| `signeros-1.0.3-x86_64.img` | `d2700a84eadf10ec9a1e9f241c4a8b885e9efb9a2285d1efe2917d1b25b20cfe` | `cb362d6cf37818fb9cc2b3bf9ecdf0e2e432ec9110a165f3041a154da7e09a7c` |

Decompressing the XZ payload and parsing its embedded `newc` archive finds 445
entries, including the trailer. All names and cpio metadata agree. Only these
four file contents differ:

- `usr/bin/pcre2grep`
- `usr/bin/pcre2test`
- `usr/lib/libpcre2-posix.so.3.0.7`
- `usr/lib/libstdc++.so.6.0.33`

Outside the initramfs, the decompressed kernels differ only in the 20-byte GNU
build ID, which changes with the linked payload. The signer application and
other rootfs files are identical.

## PCRE2: erased RPATH still changes ELF layout

Libtool links the PCRE2 programs and POSIX library with absolute build-directory
RPATHs. Buildroot's `support/scripts/fix-rpath` uses patchelf to sanitize them.
Patchelf overwrites the removed strings with `X` bytes, but preserves their
length in `.dynstr`. The dependent section offsets and relocations also retain
the original layout. Consequently, the existing post-build path scan succeeds
while hashes still depend on the build directory's length.

For example, `libpcre2-posix.so.3.0.7` has 61 placeholder bytes in the release
and 65 in the local build. `pcre2grep` has `DT_STRSZ=1240` in the release and
1244 locally.

**Causal verification:** rebuilding the original PCRE2 recipe in a directory
four characters shorter than the original local package directory, then applying
Buildroot's RPATH sanitization and strip options, reproduces all three release
files byte for byte. Rebuilds in two directories of different lengths disagree
with the original recipe.

**Fix:** the external tree adds a PCRE2 post-configure hook which clears
`hardcode_libdir_flag_spec` and disables libtool's `LD_RUN_PATH` mechanism before
linking. Both are necessary: clearing only the first fixes the executables but
leaves the POSIX library dependent on the build path. Target libraries remain
in the standard `/usr/lib` search directory.

With both changes, independent PCRE2 rebuilds in two differently sized paths
produce identical binaries and libraries. The normal Buildroot build produces
the same corrected files as those experiments.

## libstdc++: host msgfmt silently controls NLS

GCC's `libstdc++-v3/acinclude.m4`, `GLIBCXX_ENABLE_CLOCALE`, enables NLS by
default and probes for the build host's `msgfmt`. When it is present, the library
uses gettext for exception messages. The local `config.log` records
`ac_cv_prog_check_msgfmt=no`, `USE_NLS='no'`; the release library imports
`gettext`, whereas the original local library does not.

`BR2_SYSTEM_ENABLE_NLS` is already disabled, but GCC uses a custom configure
command in `package/gcc/gcc-final/gcc-final.mk`. That command does not inherit
the generic host-autotools `--disable-nls` option.

**Causal verification:** recompiling the NLS-dependent libstdc++ objects with
`_GLIBCXX_USE_NLS=1`, regenerating the affected assembly, and relinking produces
the exact release library after the normal strip step:

```text
f9f547d993d0f972db80953302abfd42b75cf54cf031c849f6bd5d56825c6b0c
```

**Fix:** `BR2_EXTRA_GCC_CONFIG_OPTIONS="--disable-nls"` explicitly pins the GCC
choice. Actual libstdc++ configure runs with the msgfmt probe forced to both
`yes` and `no` now produce `USE_NLS='no'` and leave `_GLIBCXX_USE_NLS` undefined.

The post-build hook checks the generated PCRE2 libtool configuration and the
built libstdc++ configuration, so stale incremental packages fail with rebuild
instructions rather than silently retaining these defects.

## Disk image wrapper

Reassembling the downloaded `bzImage` with the repository's post-image script,
the existing Buildroot host tools, `SOURCE_DATE_EPOCH=1781643700`, `TZ=UTC` and
`LC_ALL=C` reproduces the downloaded disk image's complete SHA-256:

```text
d2700a84eadf10ec9a1e9f241c4a8b885e9efb9a2285d1efe2917d1b25b20cfe
```

Thus no additional disk-wrapper defect is needed to explain this pair of
artifacts. The UTC environment matters when invoking post-image manually;
Buildroot normally exports it itself.

## Rebuilding and release handling

The corrected recipe changes the payload. Its hashes must not be substituted
for the existing v1.0.3 download hashes: publish a new release from the corrected
source with new checksums. Matching an old, environment-dependent hash by
imitating its directory length and installed host tools is useful forensic
evidence, not the build recipe going forward.

For a release rebuild, use a fresh output directory, or preserve any needed
artifacts and rebuild the existing output from scratch:

```bash
./scripts/build.sh --clean
./scripts/build.sh
make test
sha256sum output/images/bzImage output/images/signeros-1.0.3-x86_64.img
```

Changing the defconfig alone does not rebuild a cached toolchain. The local
verification could reuse its existing toolchain because its libstdc++ already
had NLS disabled; PCRE2 was rebuilt from scratch and both kernel/image variants
were regenerated. No second full toolchain-and-Qt build on another host was
performed. The cross-directory package rebuilds and NLS configure experiments
specifically validate the two defects identified here.

## Corrected local artifacts and validation

Both corrected images were built successfully. `make check-scripts` passed.
The QEMU harness passed the signing self-test (including independent BIP143
signature verification), runtime checks, and the production GUI framebuffer
check. Logs and screenshots are in `output/qemu-test/` on the investigated host.

| Corrected artifact | SHA-256 |
| --- | --- |
| `bzImage` | `5d288d6008e83cc10a175009108dd8e8f48fec62dd3f5edfb718a4278f5c85ba` |
| `signeros-1.0.3-x86_64.img` | `0704dfb4f4f09e1299c912d9081cfedcbf62b62d4d4d7ffbb321a85b6102df9f` |
| `bzImage-selftest` | `f6e7d55714221b34910bbfdca0a3af2a4719d0d40abe9530e80847df99845442` |
| `signeros-test-1.0.3-x86_64.img` | `9c347ce0a55c3cce2bd4a1b65db2f09447ab2bb15f049be15b2e1a91219cb7eb` |

These are local validation artifacts, not replacement checksums for the
published v1.0.3 assets. The original local images were preserved in
`/tmp/signeros-repro/original-images/`; forensic logs and experiment outputs are
under `/tmp/signeros-repro/`.

A subsequent `./scripts/build.sh --jobs 8 --no-test-image` also completed.
`sha256sum -c` against the first corrected build passed for `rootfs.cpio`,
`bzImage`, and the production disk image: all three reproduced byte for byte.
