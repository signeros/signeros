/* SPDX-License-Identifier: MIT
 *
 * signeros-ramwipe - overwrite free physical memory at shutdown.
 *
 * Run by /etc/init.d/S00early's stop action, i.e. after the kiosk has exited
 * and the data partition has been unmounted.
 *
 * What it is for: pages that once held a mnemonic, a BIP39 seed or a derived
 * private key and have since been freed. The kiosk wipes its own buffers in
 * their destructors and the kernel is built with init_on_free=1, so those pages
 * should already be zero. This is the layer that catches what neither of those
 * did - a page freed by a library we do not control, a page of page cache that
 * held the PSBT, a fragment left by an abnormal exit.
 *
 * What it is NOT: a defence against a cold-boot attack. Once the DIMMs are
 * powered, the data is out of software's reach. See README, "Threat model".
 *
 * Safety: allocation is bounded by re-reading /proc/meminfo before every chunk
 * and stopping while a reserve is still free, and this process sets its own
 * oom_score_adj to the maximum so that if the kernel does have to kill
 * something, it kills the wiper and not init.
 */

/* O_CLOEXEC and MAP_ANONYMOUS are POSIX-2008/GNU extensions; ask for them
 * explicitly so this file also compiles under a strict -std=c11. */
#define _GNU_SOURCE 1

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define CHUNK_MIB          64
#define DEFAULT_RESERVE_MIB 96
#define MAX_CHUNKS         4096          /* 256 GiB ceiling */
#define MIB                (1024UL * 1024UL)

/* Reads a single "Key:  <value> kB" field out of /proc/meminfo. Returns KiB, or
 * 0 when the field is absent. */
static unsigned long meminfo_kib(const char *key)
{
    FILE *f = fopen("/proc/meminfo", "r");
    char line[256];
    size_t keylen;
    unsigned long value = 0;

    if (f == NULL)
        return 0;

    keylen = strlen(key);
    while (fgets(line, sizeof(line), f) != NULL) {
        if (strncmp(line, key, keylen) == 0 && line[keylen] == ':') {
            value = strtoul(line + keylen + 1, NULL, 10);
            break;
        }
    }
    fclose(f);
    return value;
}

static void make_ourselves_the_oom_victim(void)
{
    int fd = open("/proc/self/oom_score_adj", O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
        (void)!write(fd, "1000\n", 5);
        close(fd);
    }
}

int main(int argc, char **argv)
{
    unsigned long reserve_mib = DEFAULT_RESERVE_MIB;
    int verbose = 0;
    int i;

    void *chunks[MAX_CHUNKS];
    size_t nchunks = 0;
    unsigned long wiped_mib = 0;

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--reserve-mib") == 0 && i + 1 < argc) {
            reserve_mib = strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "--help") == 0) {
            fprintf(stderr,
                    "usage: signeros-ramwipe [--reserve-mib N] [--verbose]\n"
                    "  Overwrites free memory with 0xff then 0x00, keeping N MiB free.\n");
            return 0;
        } else {
            fprintf(stderr, "signeros-ramwipe: unknown argument '%s'\n", argv[i]);
            return 2;
        }
    }

    if (reserve_mib < 32)
        reserve_mib = 32;   /* never squeeze init out of memory */

    make_ourselves_the_oom_victim();

    while (nchunks < MAX_CHUNKS) {
        unsigned long avail_mib;
        unsigned char *p;
        size_t off;

        /* Re-read before every chunk: this is what keeps the loop from ever
         * driving the system into OOM, regardless of what else is running. */
        avail_mib = meminfo_kib("MemAvailable") / 1024UL;
        if (avail_mib == 0)
            avail_mib = meminfo_kib("MemFree") / 1024UL;
        if (avail_mib <= reserve_mib + CHUNK_MIB)
            break;

        p = mmap(NULL, (size_t)CHUNK_MIB * MIB, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
        if (p == MAP_FAILED)
            break;

        /* Two passes. 0xff first so that a page which "looks zeroed" cannot be
         * mistaken for one that was actually written, then 0x00 so nothing is
         * left holding a recognisable pattern. The barrier after each megabyte
         * stops the compiler treating these stores as dead once the mapping
         * goes away.
         */
        for (off = 0; off < (size_t)CHUNK_MIB * MIB; off += MIB) {
            memset(p + off, 0xff, MIB);
            __asm__ __volatile__("" : : "r"(p + off) : "memory");
        }
        for (off = 0; off < (size_t)CHUNK_MIB * MIB; off += MIB) {
            memset(p + off, 0x00, MIB);
            __asm__ __volatile__("" : : "r"(p + off) : "memory");
        }

        chunks[nchunks++] = p;
        wiped_mib += CHUNK_MIB;

        if (verbose)
            fprintf(stderr, "signeros-ramwipe: %lu MiB scrubbed, %lu MiB available\n",
                    wiped_mib, avail_mib);
    }

    /* Hand it all back. The pages are zero now; init_on_alloc=1 means whoever
     * gets them next sees zeroes too. */
    for (i = 0; i < (int)nchunks; ++i)
        munmap(chunks[i], (size_t)CHUNK_MIB * MIB);

    printf("signeros-ramwipe: scrubbed %lu MiB of free memory (reserve %lu MiB)\n",
           wiped_mib, reserve_mib);
    return 0;
}
