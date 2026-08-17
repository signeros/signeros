// SPDX-License-Identifier: MIT

#include "psbt_engine.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <ctime>

#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_bip39.h>
#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_map.h>
#include <wally_psbt.h>
#include <wally_script.h>
#include <wally_transaction.h>

namespace signeros {
// ---------------------------------------------------------------------------
// The one and only place a BIP32 master private key can live.
//
// Static storage, page-locked, wiped on clear. Not a member of PsbtEngine on
// purpose: PsbtEngine instances are owned by Qt widgets and would therefore be
// heap-allocated, and a heap-allocated master key can be left behind by a
// reallocation or a missed destructor. There is at most one key resident at any
// moment, which is also the correct semantics for this device.
//
// Declared in the header (processMasterKey) so that wallet creation derives
// into these same pages instead of opening a second slot of its own.
// ---------------------------------------------------------------------------
SecureObject<ext_key> &processMasterKey()
{
    static SecureObject<ext_key> key;
    return key;
}

namespace {

SecureObject<ext_key> &masterKey()
{
    return processMasterKey();
}

constexpr std::size_t kMaxPsbtBytes = 1u << 20;   // 1 MiB. Real PSBTs are KBs.
constexpr std::size_t kFingerprintLen = 4;
constexpr std::size_t kMaxPathElements = 32;

// Signature sizes used by the vsize estimator. A GRIND_R (low-R) DER signature
// is 71 bytes plus the sighash byte; using 72 keeps the estimate on the
// conservative side of reality, which is the right direction for a fee display.
constexpr std::size_t kDerSigLen = 72;
constexpr std::size_t kCompressedPubkeyLen = 33;

std::string hexOf(const unsigned char *bytes, std::size_t len)
{
    if (bytes == nullptr || len == 0)
        return {};
    char *hex = nullptr;
    if (wally_hex_from_bytes(bytes, len, &hex) != WALLY_OK || hex == nullptr)
        return {};
    std::string out(hex);
    wally_free_string(hex);
    return out;
}

// Bitcoin displays txids byte-reversed relative to their internal form.
std::string txidToDisplay(const unsigned char *hash32)
{
    unsigned char rev[WALLY_TXHASH_LEN];
    for (std::size_t i = 0; i < WALLY_TXHASH_LEN; ++i)
        rev[i] = hash32[WALLY_TXHASH_LEN - 1 - i];
    return hexOf(rev, sizeof(rev));
}

std::string formatPath(const std::uint32_t *path, std::size_t len)
{
    std::string out = "m";
    char buf[24];
    for (std::size_t i = 0; i < len; ++i) {
        const std::uint32_t e = path[i];
        if (e & 0x80000000u)
            std::snprintf(buf, sizeof(buf), "/%u'", e & 0x7fffffffu);
        else
            std::snprintf(buf, sizeof(buf), "/%u", e);
        out += buf;
    }
    return out;
}

std::vector<std::string> splitPath(const std::string &path)
{
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (start <= path.size()) {
        const std::size_t slash = path.find('/', start);
        if (slash == std::string::npos) {
            parts.push_back(path.substr(start));
            break;
        }
        parts.push_back(path.substr(start, slash - start));
        start = slash + 1;
    }
    return parts;
}

// "m/84'/0'/0'/1/7" -> "m/84'/0'/0'": purpose, coin type and account, which is
// the granularity a wallet is watched at.
std::string pathAccountPrefix(const std::string &path)
{
    const std::vector<std::string> parts = splitPath(path);
    if (parts.size() < 5)
        return {};
    return parts[0] + "/" + parts[1] + "/" + parts[2] + "/" + parts[3];
}

// The branch element: 0 for receive, 1 for change, by BIP44 convention.
std::string pathChainElement(const std::string &path)
{
    const std::vector<std::string> parts = splitPath(path);
    if (parts.size() < 3)
        return {};
    return parts[parts.size() - 2];
}

// Reads keypath entry `index` out of a wally keypath map.
bool keypathEntry(const wally_map *map, std::size_t index,
                  std::string *fingerprintHex, std::string *path)
{
    unsigned char fp[kFingerprintLen] = {};
    if (wally_map_keypath_get_item_fingerprint(map, index, fp, sizeof(fp)) != WALLY_OK)
        return false;
    if (fingerprintHex != nullptr)
        *fingerprintHex = hexOf(fp, sizeof(fp));

    if (path != nullptr) {
        std::size_t pathLen = 0;
        if (wally_map_keypath_get_item_path_len(map, index, &pathLen) == WALLY_OK &&
            pathLen > 0 && pathLen <= kMaxPathElements) {
            std::uint32_t elems[kMaxPathElements] = {};
            std::size_t written = 0;
            if (wally_map_keypath_get_item_path(map, index, elems, pathLen, &written) == WALLY_OK)
                *path = formatPath(elems, written);
        }
    }
    return true;
}

// The raw path elements behind keypathEntry(), which are what derivation needs.
bool keypathElements(const wally_map *map, std::size_t index,
                     std::uint32_t *elems, std::size_t capacity, std::size_t *written)
{
    std::size_t pathLen = 0;
    if (wally_map_keypath_get_item_path_len(map, index, &pathLen) != WALLY_OK)
        return false;
    if (pathLen == 0 || pathLen > capacity)
        return false;
    return wally_map_keypath_get_item_path(map, index, elems, capacity, written) == WALLY_OK &&
           *written > 0;
}

// ---------------------------------------------------------------------------
// Output ownership: proving, rather than believing, that an output is change.
//
// libwally keeps an output's redeem and witness scripts in its psbt_fields map,
// keyed by the BIP174 keytype byte. Those two values are fixed by the BIP, so
// reading the map directly is stable across library versions; there is no
// public accessor for the output side of these two fields.
// ---------------------------------------------------------------------------
constexpr std::uint32_t kPsbtOutRedeemScript = 0x00;
constexpr std::uint32_t kPsbtOutWitnessScript = 0x01;

const wally_map_item *psbtField(const wally_map *fields, std::uint32_t keyType)
{
    const wally_map_item *item = wally_map_get_integer(fields, keyType);
    if (item == nullptr || item->value == nullptr || item->value_len == 0)
        return nullptr;
    return item;
}

// A scriptPubKey built from a key, kept on the stack. 64 bytes covers every
// form below with room to spare (p2tr, the longest, is 34).
struct BuiltScript {
    unsigned char bytes[64] = {};
    std::size_t len = 0;
    bool ok = false;
};

bool sameScript(const BuiltScript &a, const unsigned char *b, std::size_t bLen)
{
    return a.ok && a.len > 0 && b != nullptr && a.len == bLen &&
           std::memcmp(a.bytes, b, bLen) == 0;
}

BuiltScript p2pkhFor(const unsigned char *pub)
{
    BuiltScript s;
    s.ok = wally_scriptpubkey_p2pkh_from_bytes(pub, EC_PUBLIC_KEY_LEN,
                                               WALLY_SCRIPT_HASH160,
                                               s.bytes, sizeof(s.bytes), &s.len) == WALLY_OK;
    return s;
}

BuiltScript p2wpkhFor(const unsigned char *pub)
{
    BuiltScript s;
    s.ok = wally_witness_program_from_bytes(pub, EC_PUBLIC_KEY_LEN,
                                            WALLY_SCRIPT_HASH160,
                                            s.bytes, sizeof(s.bytes), &s.len) == WALLY_OK;
    return s;
}

// A compressed pubkey is tweaked per BIP341 by libwally itself, so this is the
// key-path-only taproot output for `pub` - which is what a change output is.
BuiltScript p2trFor(const unsigned char *pub)
{
    BuiltScript s;
    s.ok = wally_scriptpubkey_p2tr_from_bytes(pub, EC_PUBLIC_KEY_LEN, 0,
                                              s.bytes, sizeof(s.bytes), &s.len) == WALLY_OK;
    return s;
}

BuiltScript p2shOf(const unsigned char *script, std::size_t len)
{
    BuiltScript s;
    s.ok = wally_scriptpubkey_p2sh_from_bytes(script, len, WALLY_SCRIPT_HASH160,
                                              s.bytes, sizeof(s.bytes), &s.len) == WALLY_OK;
    return s;
}

BuiltScript p2wshOf(const unsigned char *script, std::size_t len)
{
    BuiltScript s;
    s.ok = wally_witness_program_from_bytes(script, len, WALLY_SCRIPT_SHA256,
                                            s.bytes, sizeof(s.bytes), &s.len) == WALLY_OK;
    return s;
}

// Does `needle` appear verbatim in `haystack`? This is how a multisig script is
// tied back to us: our public key has to be one of the keys the script names.
bool containsBytes(const unsigned char *haystack, std::size_t hayLen,
                   const unsigned char *needle, std::size_t needleLen)
{
    if (haystack == nullptr || needle == nullptr || needleLen == 0 || hayLen < needleLen)
        return false;
    for (std::size_t i = 0; i + needleLen <= hayLen; ++i)
        if (std::memcmp(haystack + i, needle, needleLen) == 0)
            return true;
    return false;
}

// Given a public key we derived ourselves, decide what `spk` really is.
//
// Every branch reconstructs the scriptPubKey the key would produce and compares
// bytes. Nothing here trusts a label in the file. Where the PSBT supplies the
// script behind a script-hash output, that script is checked to hash to the
// output *and* to contain our key; where it does not supply one, the answer is
// Unverifiable rather than a guess in either direction.
OutputOwnership ownershipForScript(const unsigned char *pub,
                                   const unsigned char *spk, std::size_t spkLen,
                                   const wally_map_item *redeem,
                                   const wally_map_item *witnessScript,
                                   bool hasTaprootTree)
{
    if (pub == nullptr || spk == nullptr || spkLen == 0)
        return OutputOwnership::Unverifiable;

    std::size_t type = 0;
    wally_scriptpubkey_get_type(spk, spkLen, &type);

    switch (type) {
    case WALLY_SCRIPT_TYPE_P2PKH:
        return sameScript(p2pkhFor(pub), spk, spkLen) ? OutputOwnership::Verified
                                                      : OutputOwnership::Mismatch;

    case WALLY_SCRIPT_TYPE_P2WPKH:
        return sameScript(p2wpkhFor(pub), spk, spkLen) ? OutputOwnership::Verified
                                                       : OutputOwnership::Mismatch;

    case WALLY_SCRIPT_TYPE_P2TR:
        if (sameScript(p2trFor(pub), spk, spkLen))
            return OutputOwnership::Verified;
        // A key-path output is the only taproot form that can be rebuilt from a
        // public key alone. With a script tree present the output commits to
        // more than we were given, so this is "cannot tell", not "wrong".
        return hasTaprootTree ? OutputOwnership::Unverifiable : OutputOwnership::Mismatch;

    case WALLY_SCRIPT_TYPE_P2WSH:
        if (witnessScript == nullptr)
            return OutputOwnership::Unverifiable;
        if (!sameScript(p2wshOf(witnessScript->value, witnessScript->value_len), spk, spkLen))
            return OutputOwnership::Mismatch;
        return containsBytes(witnessScript->value, witnessScript->value_len,
                             pub, EC_PUBLIC_KEY_LEN)
                   ? OutputOwnership::Verified
                   : OutputOwnership::Mismatch;

    case WALLY_SCRIPT_TYPE_P2SH: {
        if (redeem == nullptr) {
            // The only p2sh form rebuildable from a key alone: p2sh-p2wpkh.
            const BuiltScript wp = p2wpkhFor(pub);
            if (wp.ok && sameScript(p2shOf(wp.bytes, wp.len), spk, spkLen))
                return OutputOwnership::Verified;
            return OutputOwnership::Unverifiable;
        }

        // The PSBT handed us a redeem script; it must hash to this output.
        if (!sameScript(p2shOf(redeem->value, redeem->value_len), spk, spkLen))
            return OutputOwnership::Mismatch;

        const BuiltScript wp = p2wpkhFor(pub);
        if (wp.ok && wp.len == redeem->value_len &&
            std::memcmp(wp.bytes, redeem->value, wp.len) == 0)
            return OutputOwnership::Verified;   // p2sh-p2wpkh

        // p2sh-p2wsh: the redeem script is a v0 witness program over sha256 of
        // the witness script, which is where our key has to appear.
        if (redeem->value_len == 34 && redeem->value[0] == 0x00 && redeem->value[1] == 0x20) {
            if (witnessScript == nullptr)
                return OutputOwnership::Unverifiable;
            const BuiltScript ws = p2wshOf(witnessScript->value, witnessScript->value_len);
            if (!ws.ok || ws.len != redeem->value_len ||
                std::memcmp(ws.bytes, redeem->value, ws.len) != 0)
                return OutputOwnership::Mismatch;
            return containsBytes(witnessScript->value, witnessScript->value_len,
                                 pub, EC_PUBLIC_KEY_LEN)
                       ? OutputOwnership::Verified
                       : OutputOwnership::Mismatch;
        }

        // Anything else inside p2sh (bare multisig, for one) is ours only if it
        // names our key.
        return containsBytes(redeem->value, redeem->value_len, pub, EC_PUBLIC_KEY_LEN)
                   ? OutputOwnership::Verified
                   : OutputOwnership::Mismatch;
    }

    default:
        return OutputOwnership::Unverifiable;
    }
}

std::size_t pushOverhead(std::size_t dataLen)
{
    if (dataLen < 76)
        return 1;                 // direct push opcode
    if (dataLen < 256)
        return 2;                 // OP_PUSHDATA1 + len
    return 3;                     // OP_PUSHDATA2 + len16
}

std::size_t varintLen(std::size_t v)
{
    if (v < 0xfd)
        return 1;
    if (v <= 0xffff)
        return 3;
    if (v <= 0xffffffffu)
        return 5;
    return 9;
}

// m of an m-of-n bare multisig script: OP_m is 0x51..0x60.
std::size_t multisigM(const unsigned char *script, std::size_t len)
{
    if (script == nullptr || len == 0)
        return 0;
    const unsigned char op = script[0];
    if (op >= 0x51 && op <= 0x60)
        return static_cast<std::size_t>(op - 0x50);
    return 0;
}

bool isWitnessV0Pkh(const unsigned char *s, std::size_t len)
{
    return len == 22 && s[0] == 0x00 && s[1] == 0x14;
}

bool isWitnessV0Sh(const unsigned char *s, std::size_t len)
{
    return len == 34 && s[0] == 0x00 && s[1] == 0x20;
}

const char *scriptTypeName(std::size_t type)
{
    switch (type) {
    case WALLY_SCRIPT_TYPE_P2PKH:     return "p2pkh";
    case WALLY_SCRIPT_TYPE_P2SH:      return "p2sh";
    case WALLY_SCRIPT_TYPE_P2WPKH:    return "p2wpkh";
    case WALLY_SCRIPT_TYPE_P2WSH:     return "p2wsh";
    case WALLY_SCRIPT_TYPE_P2TR:      return "p2tr";
    case WALLY_SCRIPT_TYPE_MULTISIG:  return "bare-multisig";
    case WALLY_SCRIPT_TYPE_OP_RETURN: return "op-return";
    default:                          return "non-standard";
    }
}

std::uint32_t networkAddressVersion(Network n)
{
    switch (n) {
    case Network::Mainnet: return WALLY_NETWORK_BITCOIN_MAINNET;
    case Network::Regtest: return WALLY_NETWORK_BITCOIN_REGTEST;
    case Network::Testnet:
    case Network::Signet:
    default:               return WALLY_NETWORK_BITCOIN_TESTNET;
    }
}

const char *networkBech32Hrp(Network n)
{
    switch (n) {
    case Network::Mainnet: return "bc";
    case Network::Regtest: return "bcrt";
    case Network::Testnet:
    case Network::Signet:
    default:               return "tb";
    }
}

std::uint32_t networkBip32Version(Network n, bool priv)
{
    if (n == Network::Mainnet)
        return priv ? BIP32_VER_MAIN_PRIVATE : BIP32_VER_MAIN_PUBLIC;
    return priv ? BIP32_VER_TEST_PRIVATE : BIP32_VER_TEST_PUBLIC;
}

// Reads the whole of a small file. Used for the PSBT (untrusted) and for the
// self-test mnemonic file.
bool readFileCapped(const std::string &path, std::size_t cap,
                    std::vector<unsigned char> *out, std::string *err)
{
    out->clear();

    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (err) *err = "cannot open " + path;
        return false;
    }

    struct stat st {};
    if (::fstat(fd, &st) != 0) {
        ::close(fd);
        if (err) *err = "cannot stat " + path;
        return false;
    }
    if (!S_ISREG(st.st_mode)) {
        ::close(fd);
        if (err) *err = path + " is not a regular file";
        return false;
    }
    if (static_cast<std::size_t>(st.st_size) > cap) {
        ::close(fd);
        if (err) *err = path + " is larger than the " +
                        std::to_string(cap / 1024) + " KiB limit for a PSBT";
        return false;
    }

    out->resize(static_cast<std::size_t>(st.st_size));
    std::size_t got = 0;
    while (got < out->size()) {
        const ssize_t n = ::read(fd, out->data() + got, out->size() - got);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            ::close(fd);
            out->clear();
            if (err) *err = "read error on " + path;
            return false;
        }
        if (n == 0)
            break;
        got += static_cast<std::size_t>(n);
    }
    ::close(fd);
    out->resize(got);
    return true;
}

} // namespace

// ---------------------------------------------------------------------------
// Output file names
// ---------------------------------------------------------------------------

std::string fileTimestamp(bool *clockLooksUnset)
{
    const std::time_t now = std::time(nullptr);
    std::tm tm {};
    char buf[32];

    if (now > 0 && ::localtime_r(&now, &tm) != nullptr && (tm.tm_year + 1900) >= 2020) {
        if (clockLooksUnset) *clockLooksUnset = false;
        std::snprintf(buf, sizeof(buf), "%04d%02d%02d-%02d%02d%02d",
                      tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                      tm.tm_hour, tm.tm_min, tm.tm_sec);
        return buf;
    }

    // No usable RTC. Still produce a unique, monotonic name rather than
    // silently overwriting, and let the caller warn the user.
    if (clockLooksUnset) *clockLooksUnset = true;
    struct sysinfo si {};
    long up = 0;
    if (::sysinfo(&si) == 0)
        up = si.uptime;
    std::snprintf(buf, sizeof(buf), "noclock-%06ld", up);
    return buf;
}

std::string sanitiseFileName(const std::string &name, const std::string &suffix)
{
    // Everything after the last slash. A name is one path component, and the
    // operator typing one is not a reason to let them write outside the data
    // partition - or into a subdirectory of it that does not exist.
    std::string base = name;
    const std::size_t slash = base.find_last_of('/');
    if (slash != std::string::npos)
        base = base.substr(slash + 1);

    std::string out;
    out.reserve(base.size() + suffix.size());
    for (const char c : base) {
        // Printable ASCII only, minus the ones that are a path, a wildcard or a
        // quoting problem somewhere downstream. The stick is FAT and the file
        // is read on somebody else's computer.
        if (c < 0x20 || c > 0x7e)
            continue;
        if (std::strchr("\\:*?\"<>|", c) != nullptr)
            continue;
        // No leading dots: neither a hidden file nor the two special entries.
        if (c == '.' && out.empty())
            continue;
        out += c;
    }

    // Trailing spaces and dots are legal to type and a nuisance on FAT.
    while (!out.empty() && (out.back() == ' ' || out.back() == '.'))
        out.pop_back();
    // Leading spaces too, now that the dots are gone.
    std::size_t first = 0;
    while (first < out.size() && out[first] == ' ')
        ++first;
    out = out.substr(first);

    if (out.empty())
        return std::string();

    if (!suffix.empty()) {
        const bool hasSuffix =
            out.size() > suffix.size() &&
            out.compare(out.size() - suffix.size(), suffix.size(), suffix) == 0;
        if (!hasSuffix)
            out += suffix;
    }
    return out;
}

std::string freeFileName(const std::string &dir, const std::string &stem,
                         const std::string &suffix)
{
    std::string candidate = stem + suffix;
    for (int attempt = 2; attempt < 1000; ++attempt) {
        if (::access((dir + "/" + candidate).c_str(), F_OK) != 0)
            return candidate;
        candidate = stem + "-" + std::to_string(attempt) + suffix;
    }
    return candidate;
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

Network networkFromString(const std::string &s, bool *ok)
{
    if (ok) *ok = true;
    if (s == "mainnet" || s == "bitcoin" || s == "main") return Network::Mainnet;
    if (s == "testnet" || s == "test" || s == "testnet3" || s == "testnet4") return Network::Testnet;
    if (s == "signet") return Network::Signet;
    if (s == "regtest") return Network::Regtest;
    if (ok) *ok = false;
    return Network::Mainnet;
}

const char *networkName(Network n)
{
    switch (n) {
    case Network::Mainnet: return "mainnet";
    case Network::Testnet: return "testnet";
    case Network::Signet:  return "signet";
    case Network::Regtest: return "regtest";
    }
    return "mainnet";
}

const char *ownershipName(OutputOwnership o)
{
    switch (o) {
    case OutputOwnership::ThirdParty:   return "third-party";
    case OutputOwnership::Claimed:      return "claimed-unverified";
    case OutputOwnership::Verified:     return "verified-change";
    case OutputOwnership::Unverifiable: return "claimed-unverifiable";
    case OutputOwnership::Mismatch:     return "MISMATCH";
    }
    return "third-party";
}

std::string formatBtc(std::uint64_t satoshi)
{
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%" PRIu64 ".%08" PRIu64,
                  static_cast<std::uint64_t>(satoshi / 100000000ull),
                  static_cast<std::uint64_t>(satoshi % 100000000ull));
    return buf;
}

std::string formatSat(std::uint64_t satoshi)
{
    std::string digits = std::to_string(satoshi);
    std::string out;
    const std::size_t n = digits.size();
    for (std::size_t i = 0; i < n; ++i) {
        if (i > 0 && ((n - i) % 3) == 0)
            out += ' ';
        out += digits[i];
    }
    return out;
}

std::string formatFeeRate(double satPerVbyte)
{
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.1f", satPerVbyte);
    return buf;
}

std::vector<PsbtFileEntry> listPsbtFiles(const std::string &dir)
{
    std::vector<PsbtFileEntry> out;

    DIR *d = ::opendir(dir.c_str());
    if (d == nullptr)
        return out;

    while (const struct dirent *de = ::readdir(d)) {
        const std::string name = de->d_name;
        if (name.empty() || name[0] == '.')
            continue;
        if (name.size() < 6)
            continue;

        // Case-insensitive ".psbt" suffix.
        const std::string suffix = name.substr(name.size() - 5);
        std::string lowered;
        for (char c : suffix)
            lowered += static_cast<char>((c >= 'A' && c <= 'Z') ? c + 32 : c);
        if (lowered != ".psbt")
            continue;

        PsbtFileEntry e;
        e.name = name;
        e.path = dir + "/" + name;

        struct stat st {};
        if (::stat(e.path.c_str(), &st) != 0 || !S_ISREG(st.st_mode))
            continue;
        e.sizeBytes = static_cast<std::uint64_t>(st.st_size);
        e.mtime = static_cast<std::int64_t>(st.st_mtime);
        e.isSignerOutput = (name.rfind("signed_", 0) == 0);

        out.push_back(std::move(e));
    }
    ::closedir(d);

    std::sort(out.begin(), out.end(), [](const PsbtFileEntry &a, const PsbtFileEntry &b) {
        if (a.isSignerOutput != b.isSignerOutput)
            return !a.isSignerOutput;          // inputs first
        if (a.mtime != b.mtime)
            return a.mtime > b.mtime;          // newest first
        return a.name < b.name;
    });

    return out;
}

void bip39Suggestions(const char *prefix, std::size_t maxResults,
                      std::vector<std::string> *out)
{
    out->clear();
    if (prefix == nullptr || prefix[0] == '\0' || maxResults == 0)
        return;

    struct words *wl = nullptr;
    if (bip39_get_wordlist(nullptr, &wl) != WALLY_OK || wl == nullptr)
        return;

    const std::size_t prefixLen = std::strlen(prefix);
    for (std::size_t i = 0; i < 2048 && out->size() < maxResults; ++i) {
        char *word = nullptr;
        if (bip39_get_word(wl, i, &word) != WALLY_OK || word == nullptr)
            continue;
        if (std::strncmp(word, prefix, prefixLen) == 0)
            out->emplace_back(word);
        wally_free_string(word);
    }
}

bool bip39Validate(const SecureString &mnemonic, std::string *err)
{
    struct words *wl = nullptr;
    if (bip39_get_wordlist(nullptr, &wl) != WALLY_OK || wl == nullptr) {
        if (err) *err = "the BIP39 wordlist is unavailable";
        return false;
    }
    if (bip39_mnemonic_validate(wl, mnemonic.c_str()) != WALLY_OK) {
        if (err)
            *err = "that is not a valid BIP39 mnemonic: either a word is not in "
                   "the wordlist, or the checksum does not match. Check the "
                   "word count (12, 15, 18, 21 or 24) and the spelling.";
        return false;
    }
    return true;
}

std::uint32_t bip39UnknownSlots(const SecureString &mnemonic, int inProgressSlot)
{
    const std::size_t cellCount = mnemonic.slotCount();
    if (cellCount == 0)
        return 0;

    // Start with every non-empty slot suspect and clear the bits as the
    // wordlist accounts for them, so a wordlist that cannot be read reports
    // everything unknown rather than everything fine.
    std::uint32_t unknown = 0;
    const std::size_t limit = (cellCount < 32) ? cellCount : 32;
    for (std::size_t i = 0; i < limit; ++i) {
        if (inProgressSlot >= 0 && static_cast<std::size_t>(inProgressSlot) == i)
            continue;
        if (mnemonic.slotLength(i) > 0)
            unknown |= (1u << i);
    }
    if (unknown == 0)
        return 0;

    struct words *wl = nullptr;
    if (bip39_get_wordlist(nullptr, &wl) != WALLY_OK || wl == nullptr)
        return unknown;

    // One pass over the list, testing it against every outstanding slot -
    // rather than a lookup per cell, which would walk the 2048 words once for
    // each of twenty-four cells on every single keystroke.
    const char *buf = mnemonic.c_str();
    for (std::size_t w = 0; w < 2048 && unknown != 0; ++w) {
        char *word = nullptr;
        if (bip39_get_word(wl, w, &word) != WALLY_OK || word == nullptr)
            continue;
        const std::size_t wlen = std::strlen(word);

        for (std::size_t i = 0; i < limit; ++i) {
            if ((unknown & (1u << i)) == 0)
                continue;
            std::size_t start = 0;
            std::size_t len = 0;
            if (!mnemonic.slotSpan(i, &start, &len) || len != wlen)
                continue;
            if (std::memcmp(buf + start, word, wlen) == 0)
                unknown &= ~(1u << i);
        }
        wally_free_string(word);
    }
    return unknown;
}

// ---------------------------------------------------------------------------
// PsbtEngine
// ---------------------------------------------------------------------------

bool PsbtEngine::initLibrary(std::string *err)
{
    if (wally_init(0) != WALLY_OK) {
        if (err) *err = "libwally-core failed to initialise";
        return false;
    }

    // Blind the secp256k1 context. This protects against side-channel
    // observation of scalar multiplications; it is NOT nonce generation.
    // Signature nonces are RFC6979-deterministic inside libwally, so a weak or
    // uninitialised system RNG cannot leak a private key through a biased k.
    // That is why a failure here is a warning rather than fatal.
    SecureBuffer<32> entropy;
    const int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        std::size_t got = 0;
        while (got < entropy.capacity()) {
            const ssize_t n = ::read(fd, entropy.data() + got, entropy.capacity() - got);
            if (n <= 0)
                break;
            got += static_cast<std::size_t>(n);
        }
        ::close(fd);
        if (got == entropy.capacity())
            wally_secp_randomize(entropy.data(), entropy.capacity());
        else if (err)
            *err = "warning: could not read 32 bytes from /dev/urandom; "
                   "secp256k1 context is unblinded (signing is still "
                   "deterministic per RFC6979)";
    } else if (err) {
        *err = "warning: /dev/urandom is unavailable; secp256k1 context is "
               "unblinded (signing is still deterministic per RFC6979)";
    }
    return true;
}

void PsbtEngine::shutdownLibrary()
{
    masterKey().clear();
    wally_cleanup(0);
}

std::string PsbtEngine::libraryVersion()
{
    std::uint32_t v = 0;
    if (wally_get_build_version(&v) != WALLY_OK)
        return "unknown";
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u",
                  (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff);
    return buf;
}

PsbtEngine::PsbtEngine(Network network) : network_(network) {}

PsbtEngine::~PsbtEngine()
{
    unload();
    clearKey();
}

// ---------------------------------------------------------------------------

bool PsbtEngine::load(const std::string &path, std::string *err)
{
    unload();

    std::vector<unsigned char> raw;
    if (!readFileCapped(path, kMaxPsbtBytes, &raw, err))
        return false;
    if (raw.empty()) {
        if (err) *err = "the file is empty";
        return false;
    }

    sourcePath_ = path;
    const std::size_t slash = path.find_last_of('/');
    sourceName_ = (slash == std::string::npos) ? path : path.substr(slash + 1);

    if (!parse(raw.data(), raw.size(), err)) {
        sourcePath_.clear();
        sourceName_.clear();
        return false;
    }

    resummarise();
    return true;
}

bool PsbtEngine::parse(const unsigned char *data, std::size_t len, std::string *err)
{
    static const unsigned char kMagic[5] = { 'p', 's', 'b', 't', 0xff };
    const bool binary = (len >= sizeof(kMagic) &&
                         std::memcmp(data, kMagic, sizeof(kMagic)) == 0);

    // Strict first. A signer should prefer refusing a malformed PSBT to
    // guessing what its author meant; if strict parsing fails we retry
    // permissively and say so in the findings, so the operator decides.
    int rc = WALLY_EINVAL;
    bool wasLoose = false;

    if (binary) {
        rc = wally_psbt_from_bytes(data, len, WALLY_PSBT_PARSE_FLAG_STRICT, &psbt_);
        if (rc != WALLY_OK) {
            rc = wally_psbt_from_bytes(data, len, 0, &psbt_);
            wasLoose = (rc == WALLY_OK);
        }
    } else {
        // Base64: strip all whitespace and NUL-terminate. Reject anything that
        // is not base64 before handing it to the parser.
        std::string b64;
        b64.reserve(len);
        for (std::size_t i = 0; i < len; ++i) {
            const unsigned char c = data[i];
            if (c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == '\0')
                continue;
            const bool valid = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                               (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
            if (!valid) {
                if (err)
                    *err = "this file is neither a binary PSBT (it does not start "
                           "with the psbt magic) nor base64 text";
                return false;
            }
            b64 += static_cast<char>(c);
        }
        if (b64.empty()) {
            if (err) *err = "the file contains no PSBT data";
            return false;
        }

        rc = wally_psbt_from_base64(b64.c_str(), WALLY_PSBT_PARSE_FLAG_STRICT, &psbt_);
        if (rc != WALLY_OK) {
            rc = wally_psbt_from_base64(b64.c_str(), 0, &psbt_);
            wasLoose = (rc == WALLY_OK);
        }
    }

    if (rc != WALLY_OK || psbt_ == nullptr) {
        psbt_ = nullptr;
        if (err)
            *err = "libwally could not parse this as a BIP174/BIP370 PSBT";
        return false;
    }

    // Refuse Elements/Liquid PSETs outright: this build has no confidential
    // transaction support, so it cannot show the operator what it would sign.
    std::size_t isElements = 0;
    if (wally_psbt_is_elements(psbt_, &isElements) == WALLY_OK && isElements != 0) {
        wally_psbt_free(psbt_);
        psbt_ = nullptr;
        if (err)
            *err = "this is an Elements/Liquid PSET, not a Bitcoin PSBT. "
                   "SignerOS does not sign confidential transactions.";
        return false;
    }

    looseParse_ = wasLoose;
    return true;
}

void PsbtEngine::unload()
{
    if (psbt_ != nullptr) {
        wally_psbt_free(psbt_);
        psbt_ = nullptr;
    }
    sourcePath_.clear();
    sourceName_.clear();
    summary_ = TxSummary {};
    looseParse_ = false;
}

// ---------------------------------------------------------------------------
// Inspection
// ---------------------------------------------------------------------------

std::string PsbtEngine::addressForScript(const unsigned char *script, std::size_t len,
                                         std::string *typeOut) const
{
    if (script == nullptr || len == 0) {
        if (typeOut) *typeOut = "empty";
        return "(empty script)";
    }

    std::size_t type = 0;
    wally_scriptpubkey_get_type(script, len, &type);
    if (typeOut) *typeOut = scriptTypeName(type);

    char *addr = nullptr;
    switch (type) {
    case WALLY_SCRIPT_TYPE_P2PKH:
    case WALLY_SCRIPT_TYPE_P2SH:
        if (wally_scriptpubkey_to_address(script, len, networkAddressVersion(network_),
                                          &addr) == WALLY_OK && addr != nullptr) {
            std::string out(addr);
            wally_free_string(addr);
            return out;
        }
        break;

    case WALLY_SCRIPT_TYPE_P2WPKH:
    case WALLY_SCRIPT_TYPE_P2WSH:
    case WALLY_SCRIPT_TYPE_P2TR:
        if (wally_addr_segwit_from_bytes(script, len, networkBech32Hrp(network_), 0,
                                         &addr) == WALLY_OK && addr != nullptr) {
            std::string out(addr);
            wally_free_string(addr);
            return out;
        }
        break;

    case WALLY_SCRIPT_TYPE_OP_RETURN:
        return "OP_RETURN (unspendable)";

    default:
        break;
    }

    return "(non-standard script) " + hexOf(script, std::min<std::size_t>(len, 40));
}

std::size_t PsbtEngine::estimateVsize(const wally_tx *unsignedTx) const
{
    if (unsignedTx == nullptr)
        return 0;

    // The extracted non-final transaction has empty scriptSigs and no witness
    // data, so its vsize is its plain serialised size: the exact base cost of
    // this transaction before signatures.
    std::size_t baseSize = 0;
    if (wally_tx_get_vsize(unsignedTx, &baseSize) != WALLY_OK || baseSize == 0)
        return 0;

    std::size_t extraScriptSig = 0;   // bytes added inside the base (x4 weight)
    std::size_t witnessBytes = 0;     // bytes added in the witness (x1 weight)
    bool anySegwit = false;

    for (std::size_t i = 0; i < psbt_->num_inputs; ++i) {
        const wally_psbt_input *in = &psbt_->inputs[i];

        // scriptPubKey being spent.
        const unsigned char *spk = nullptr;
        std::size_t spkLen = 0;
        if (in->witness_utxo != nullptr) {
            spk = in->witness_utxo->script;
            spkLen = in->witness_utxo->script_len;
        } else if (in->utxo != nullptr && i < unsignedTx->num_inputs) {
            const std::uint32_t vout = unsignedTx->inputs[i].index;
            if (vout < in->utxo->num_outputs) {
                spk = in->utxo->outputs[vout].script;
                spkLen = in->utxo->outputs[vout].script_len;
            }
        }

        // The redeem script for p2sh inputs, or the scriptPubKey otherwise.
        std::vector<unsigned char> signingScript;
        std::size_t ssLen = 0;
        if (wally_psbt_get_input_signing_script_len(psbt_, i, &ssLen) == WALLY_OK && ssLen > 0) {
            signingScript.resize(ssLen);
            std::size_t written = 0;
            if (wally_psbt_get_input_signing_script(psbt_, i, signingScript.data(),
                                                    signingScript.size(), &written) == WALLY_OK)
                signingScript.resize(written);
            else
                signingScript.clear();
        }

        // The scriptCode: for p2wsh/p2sh-p2wsh this is the witness script,
        // which is what tells us m-of-n.
        std::vector<unsigned char> scriptCode;
        if (!signingScript.empty()) {
            std::size_t scLen = 0;
            if (wally_psbt_get_input_scriptcode_len(psbt_, i, signingScript.data(),
                                                    signingScript.size(), &scLen) == WALLY_OK &&
                scLen > 0) {
                scriptCode.resize(scLen);
                std::size_t written = 0;
                if (wally_psbt_get_input_scriptcode(psbt_, i, signingScript.data(),
                                                    signingScript.size(), scriptCode.data(),
                                                    scriptCode.size(), &written) == WALLY_OK)
                    scriptCode.resize(written);
                else
                    scriptCode.clear();
            }
        }

        std::size_t type = 0;
        if (spk != nullptr && spkLen > 0)
            wally_scriptpubkey_get_type(spk, spkLen, &type);

        auto multisigWitness = [&](const std::vector<unsigned char> &script) {
            const std::size_t m = multisigM(script.data(), script.size());
            const std::size_t sigs = (m > 0) ? m : 1;
            // stack item count, the CHECKMULTISIG empty item, m signatures,
            // then the witness script itself
            return varintLen(sigs + 2) + 1 + sigs * (1 + kDerSigLen) +
                   pushOverhead(script.size()) + script.size();
        };

        switch (type) {
        case WALLY_SCRIPT_TYPE_P2WPKH:
            anySegwit = true;
            witnessBytes += 1 + (1 + kDerSigLen) + (1 + kCompressedPubkeyLen);
            break;

        case WALLY_SCRIPT_TYPE_P2TR:
            anySegwit = true;
            // Key-path spend: one 64-byte Schnorr signature (65 with a
            // non-default sighash byte).
            witnessBytes += 1 + 1 + 65;
            break;

        case WALLY_SCRIPT_TYPE_P2WSH:
            anySegwit = true;
            witnessBytes += scriptCode.empty()
                            ? (1 + 1 + (1 + kDerSigLen) + 1 + 34)
                            : multisigWitness(scriptCode);
            break;

        case WALLY_SCRIPT_TYPE_P2SH:
            if (isWitnessV0Pkh(signingScript.data(), signingScript.size())) {
                anySegwit = true;
                extraScriptSig += 1 + signingScript.size();   // push of the program
                witnessBytes += 1 + (1 + kDerSigLen) + (1 + kCompressedPubkeyLen);
            } else if (isWitnessV0Sh(signingScript.data(), signingScript.size())) {
                anySegwit = true;
                extraScriptSig += 1 + signingScript.size();
                witnessBytes += scriptCode.empty()
                                ? (1 + 1 + (1 + kDerSigLen) + 1 + 34)
                                : multisigWitness(scriptCode);
            } else {
                const std::size_t m = multisigM(signingScript.data(), signingScript.size());
                const std::size_t sigs = (m > 0) ? m : 1;
                extraScriptSig += 1 + sigs * (1 + kDerSigLen) +
                                  pushOverhead(signingScript.size()) + signingScript.size();
            }
            break;

        case WALLY_SCRIPT_TYPE_P2PKH:
            extraScriptSig += (1 + kDerSigLen) + (1 + kCompressedPubkeyLen);
            break;

        default:
            // Unknown script: assume a single-signature segwit input, which is
            // the cheapest plausible shape, and flag it in the findings so the
            // fee rate is not presented as exact.
            anySegwit = true;
            witnessBytes += 1 + (1 + kDerSigLen) + (1 + kCompressedPubkeyLen);
            break;
        }
    }

    const std::size_t weight = baseSize * 4 + extraScriptSig * 4 +
                               (anySegwit ? (2 + witnessBytes) : 0);
    return (weight + 3) / 4;
}

void PsbtEngine::resummarise()
{
    summary_ = TxSummary {};
    if (psbt_ == nullptr)
        return;

    summary_.psbtVersion = psbt_->version;

    std::size_t v = 0;
    if (wally_psbt_get_tx_version(psbt_, &v) == WALLY_OK)
        summary_.txVersion = static_cast<std::uint32_t>(v);
    if (wally_psbt_get_locktime(psbt_, &v) == WALLY_OK)
        summary_.locktime = static_cast<std::uint32_t>(v);

    std::size_t finalised = 0;
    if (wally_psbt_is_finalized(psbt_, &finalised) == WALLY_OK)
        summary_.alreadyFinalised = (finalised != 0);

    // One canonical view of the transaction for both PSBT versions: for v0 this
    // is the global unsigned tx, for v2 (BIP370) libwally builds it from the
    // per-input/per-output fields. Using it everywhere means the inspection
    // screen behaves identically for both.
    wally_tx *tx = nullptr;
    if (wally_psbt_extract(psbt_, WALLY_PSBT_EXTRACT_NON_FINAL, &tx) != WALLY_OK || tx == nullptr) {
        summary_.findings.push_back({ Severity::Danger,
            "This PSBT does not describe a complete transaction, so it cannot "
            "be displayed or signed safely." });
        summary_.safeToSign = false;
        summary_.blockReason = "the PSBT is missing fields required to build the transaction";
        return;
    }

    unsigned char txid[WALLY_TXHASH_LEN] = {};
    if (wally_tx_get_txid(tx, txid, sizeof(txid)) == WALLY_OK)
        summary_.txid = txidToDisplay(txid);

    // --- inputs ---------------------------------------------------------
    summary_.inputs.reserve(psbt_->num_inputs);
    bool allAmountsKnown = true;

    for (std::size_t i = 0; i < psbt_->num_inputs; ++i) {
        const wally_psbt_input *in = &psbt_->inputs[i];
        InputInfo info;

        if (i < tx->num_inputs) {
            info.outpoint = txidToDisplay(tx->inputs[i].txhash) + ":" +
                            std::to_string(tx->inputs[i].index);
            info.sequence = tx->inputs[i].sequence;
        }

        const unsigned char *spk = nullptr;
        std::size_t spkLen = 0;

        if (in->witness_utxo != nullptr) {
            spk = in->witness_utxo->script;
            spkLen = in->witness_utxo->script_len;
            info.amountSat = in->witness_utxo->satoshi;
            info.amountKnown = true;
        } else if (in->utxo != nullptr && i < tx->num_inputs) {
            const std::uint32_t vout = tx->inputs[i].index;
            if (vout < in->utxo->num_outputs) {
                spk = in->utxo->outputs[vout].script;
                spkLen = in->utxo->outputs[vout].script_len;
                info.amountSat = in->utxo->outputs[vout].satoshi;
                info.amountKnown = true;
            }
        }
#ifndef WALLY_ABI_NO_ELEMENTS
        // PSBTv2 mixed-creator transactions may carry an explicit amount even
        // without a UTXO. Accept it for display, but it is not authenticated by
        // a previous transaction, so it stays flagged below.
        else if (in->has_amount) {
            info.amountSat = in->amount;
            info.amountKnown = true;
        }
#endif

        if (!info.amountKnown)
            allAmountsKnown = false;

        if (spk != nullptr && spkLen > 0) {
            info.address = addressForScript(spk, spkLen, &info.scriptType);
        } else {
            info.address = "(previous output not provided)";
            info.scriptType = "unknown";
        }

        info.existingSignatures = in->signatures.num_items;
        info.alreadyFinal = (in->final_witness != nullptr);
        info.sighash = in->sighash;

        // First keypath, as a hint of who owns this input. Refined by
        // evaluateSignability() once a key is loaded.
        std::size_t numKeypaths = 0;
        wally_map_get_num_items(&in->keypaths, &numKeypaths);
        if (numKeypaths > 0)
            keypathEntry(&in->keypaths, 0, &info.fingerprint, &info.derivation);

        // Does this input tell a signer where its key lives?
        //
        // Taproot inputs keep their derivations in a separate map
        // (PSBT_IN_TAP_BIP32_DERIVATION), so both are counted. Counting only
        // `keypaths` would make a perfectly signable taproot PSBT look like one
        // carrying no derivation information at all - and the finding below
        // turns that into a hard refusal, so a false positive here would block
        // a valid transaction.
        std::size_t numTaprootPaths = 0;
        wally_map_get_num_items(&in->taproot_leaf_paths, &numTaprootPaths);
        if (numKeypaths > 0 || numTaprootPaths > 0)
            ++summary_.inputsWithDerivation;

        summary_.totalInSat += info.amountSat;
        summary_.inputs.push_back(std::move(info));
    }

    // --- outputs --------------------------------------------------------
    summary_.outputs.reserve(tx->num_outputs);
    for (std::size_t i = 0; i < tx->num_outputs; ++i) {
        OutputInfo info;
        info.amountSat = tx->outputs[i].satoshi;

        const unsigned char *spk = tx->outputs[i].script;
        const std::size_t spkLen = tx->outputs[i].script_len;

        if (spk != nullptr && spkLen > 0 && spk[0] == 0x6a) {
            info.isOpReturn = true;
            info.scriptType = "op-return";
            info.address = "OP_RETURN (data, unspendable)";
            if (spkLen > 1)
                info.opReturnHex = hexOf(spk + 1, spkLen - 1);
        } else {
            info.address = addressForScript(spk, spkLen, &info.scriptType);
        }

        // What the file *claims* about this output, which is all that is
        // knowable before a key exists. evaluateSignability() upgrades this to
        // Verified - or to Mismatch - once there is something to check against.
        if (i < psbt_->num_outputs && !info.isOpReturn) {
            const wally_psbt_output *po = &psbt_->outputs[i];
            for (const wally_map *kp : { &po->keypaths, &po->taproot_leaf_paths }) {
                std::size_t numKeypaths = 0;
                wally_map_get_num_items(kp, &numKeypaths);
                if (numKeypaths == 0)
                    continue;
                if (keypathEntry(kp, 0, &info.claimedFingerprint, &info.derivation)) {
                    info.ownership = OutputOwnership::Claimed;
                    break;
                }
            }
        }

        summary_.totalOutSat += info.amountSat;
        summary_.outputs.push_back(std::move(info));
    }

    // --- fee ------------------------------------------------------------
    summary_.feeKnown = allAmountsKnown && (summary_.totalInSat >= summary_.totalOutSat);
    if (summary_.feeKnown)
        summary_.feeSat = summary_.totalInSat - summary_.totalOutSat;

    summary_.estimatedVsize = estimateVsize(tx);
    if (summary_.feeKnown && summary_.estimatedVsize > 0)
        summary_.feeRate = static_cast<double>(summary_.feeSat) /
                           static_cast<double>(summary_.estimatedVsize);

    // Before the transaction is released: verifying an output means rebuilding
    // its scriptPubKey, and this is the canonical copy of it.
    evaluateSignability(tx);

    wally_tx_free(tx);

    deriveFindings();
}

void PsbtEngine::evaluateSignability(const wally_tx *tx)
{
    summary_.signableInputs = 0;
    summary_.verifiedChangeSat = 0;
    summary_.leavingSat = summary_.totalOutSat;
    summary_.ownershipChecked = false;
    if (psbt_ == nullptr)
        return;

    SecureObject<ext_key> &master = masterKey();
    if (!master.valid())
        return;

    summary_.ownershipChecked = true;
    const std::string ourFp = masterFingerprint();

    for (std::size_t i = 0; i < summary_.inputs.size() && i < psbt_->num_inputs; ++i) {
        ext_key *derived = nullptr;
        const int rc = wally_psbt_get_input_bip32_key_from_alloc(
            psbt_, i, 0, 0, master.get(), &derived);

        if (rc == WALLY_OK && derived != nullptr) {
            summary_.inputs[i].canSign = true;
            ++summary_.signableInputs;

            // Wipe before free: the derived child holds a private key.
            secureWipe(derived, sizeof(ext_key));
            bip32_key_free(derived);
        }

        // Prefer showing the keypath that belongs to *our* master.
        const wally_map *kp = &psbt_->inputs[i].keypaths;
        std::size_t n = 0;
        wally_map_get_num_items(kp, &n);
        for (std::size_t j = 0; j < n; ++j) {
            std::string fp, path;
            if (keypathEntry(kp, j, &fp, &path) && fp == ourFp) {
                summary_.inputs[i].fingerprint = fp;
                summary_.inputs[i].derivation = path;
                break;
            }
        }
    }

    // Change: the difference between "you are sending 0.4 BTC" and "you are
    // sending 0.1 BTC and 0.3 BTC is your own change".
    //
    // The fingerprint on an output is a hint about which key to try, never
    // evidence. For each keypath that names our master we derive the child key
    // and rebuild the scriptPubKey from it; only an exact match earns Verified.
    // A claim on our master that fails that test is Mismatch, which
    // deriveFindings() turns into a refusal to sign - a PSBT that mislabels an
    // attacker's address as your change is the one way this device could be
    // used to talk an operator into authorising their own loss.
    if (tx == nullptr)
        return;

    for (std::size_t i = 0; i < summary_.outputs.size() && i < psbt_->num_outputs &&
                            i < tx->num_outputs; ++i) {
        OutputInfo &out = summary_.outputs[i];
        if (out.isOpReturn)
            continue;

        const wally_psbt_output *po = &psbt_->outputs[i];
        const unsigned char *spk = tx->outputs[i].script;
        const std::size_t spkLen = tx->outputs[i].script_len;
        const wally_map_item *redeem = psbtField(&po->psbt_fields, kPsbtOutRedeemScript);
        const wally_map_item *witnessScript = psbtField(&po->psbt_fields, kPsbtOutWitnessScript);

        std::size_t treeItems = 0;
        wally_map_get_num_items(&po->taproot_tree, &treeItems);

        bool anyVerified = false, anyMismatch = false, anyUnverifiable = false;
        std::string verdictPath;

        for (const wally_map *kp : { &po->keypaths, &po->taproot_leaf_paths }) {
            std::size_t n = 0;
            wally_map_get_num_items(kp, &n);
            for (std::size_t j = 0; j < n && !anyVerified; ++j) {
                std::string fp, path;
                if (!keypathEntry(kp, j, &fp, &path) || fp != ourFp)
                    continue;

                std::uint32_t elems[kMaxPathElements] = {};
                std::size_t pathLen = 0;
                if (!keypathElements(kp, j, elems, kMaxPathElements, &pathLen)) {
                    anyUnverifiable = true;
                    continue;
                }

                ext_key child {};
                if (bip32_key_from_parent_path(master.get(), elems, pathLen,
                                               BIP32_FLAG_KEY_PUBLIC, &child) != WALLY_OK) {
                    secureWipe(&child, sizeof(child));
                    anyUnverifiable = true;
                    continue;
                }

                const OutputOwnership verdict =
                    ownershipForScript(child.pub_key, spk, spkLen,
                                       redeem, witnessScript, treeItems > 0);
                secureWipe(&child, sizeof(child));

                switch (verdict) {
                case OutputOwnership::Verified:     anyVerified = true; break;
                case OutputOwnership::Mismatch:     anyMismatch = true; break;
                default:                            anyUnverifiable = true; break;
                }
                if (verdictPath.empty() || anyVerified)
                    verdictPath = path;
                out.claimedFingerprint = fp;
            }
        }

        if (anyVerified)
            out.ownership = OutputOwnership::Verified;
        else if (anyMismatch)
            out.ownership = OutputOwnership::Mismatch;
        else if (anyUnverifiable)
            out.ownership = OutputOwnership::Unverifiable;
        else
            // No keypath here names our master. Whatever wallet the file was
            // talking about, it was not this one, so as far as the operator is
            // concerned this is money leaving. claimedFingerprint survives for
            // the path line, and clearKey() puts the claim back if the key
            // goes away.
            out.ownership = OutputOwnership::ThirdParty;

        if (!verdictPath.empty())
            out.derivation = verdictPath;

        if (out.ownership == OutputOwnership::Verified)
            summary_.verifiedChangeSat += out.amountSat;
    }

    summary_.leavingSat = (summary_.totalOutSat >= summary_.verifiedChangeSat)
                              ? summary_.totalOutSat - summary_.verifiedChangeSat
                              : 0;
}

void PsbtEngine::deriveFindings()
{
    auto add = [this](Severity s, std::string text) {
        summary_.findings.push_back({ s, std::move(text) });
    };

    summary_.safeToSign = true;
    summary_.blockReason.clear();

    auto block = [&](const std::string &reason, const std::string &text) {
        summary_.safeToSign = false;
        if (summary_.blockReason.empty())
            summary_.blockReason = reason;
        add(Severity::Danger, text);
    };

    if (looseParse_)
        add(Severity::Warning,
            "This PSBT is not strictly spec-conformant; it was accepted in "
            "permissive mode. Treat everything below with extra suspicion.");

    if (summary_.inputs.empty())
        block("the PSBT has no inputs", "This PSBT has no inputs.");

    if (summary_.outputs.empty())
        block("the PSBT has no outputs", "This PSBT has no outputs.");

    if (summary_.alreadyFinalised)
        block("the PSBT is already finalised",
              "This PSBT is already finalised. There is nothing left to sign, "
              "and adding a signature would invalidate it.");

    // The single most important refusal in the whole application.
    //
    // Without the previous output for every input, the total input value is
    // unknown, so the fee is unknown. An attacker who omits one UTXO can make a
    // transaction that looks like it pays a 500 sat fee actually pay the rest of
    // your balance to miners. A signer that guesses here is broken by design.
    std::size_t missing = 0;
    for (const InputInfo &in : summary_.inputs)
        if (!in.amountKnown)
            ++missing;
    if (missing > 0) {
        block("the PSBT does not include the UTXO for every input",
              std::to_string(missing) + " of " + std::to_string(summary_.inputs.size()) +
              " inputs come with no previous output, so the amount being spent - "
              "and therefore the fee - cannot be verified. Ask the wallet that "
              "created this PSBT to include witness_utxo or non_witness_utxo for "
              "every input, then try again.");
    }

    if (summary_.totalOutSat > summary_.totalInSat && missing == 0)
        block("outputs exceed inputs",
              "The outputs spend more than the inputs provide. This "
              "transaction is invalid.");

    // Derivation information.
    //
    // libwally's simple signer walks PSBT_IN_BIP32_DERIVATION: for each input it
    // derives the recorded path from our master and compares public keys. With
    // no derivation fields there is nothing to match, so *no* key can sign this
    // file - it is not a wrong-wallet situation and no amount of retyping the
    // mnemonic will help.
    //
    // This is a hard refusal rather than a failure at signing time, specifically
    // so that the operator is never asked to type a seed into a device that
    // cannot use it.
    if (!summary_.inputs.empty() && summary_.inputsWithDerivation == 0) {
        block("the PSBT carries no BIP32 derivation paths",
              "No input says which key should sign it: this PSBT has no BIP32 "
              "derivation fields at all. That is not a wrong-wallet problem - no "
              "signer could sign this file. Ask the wallet that created it to "
              "include the master fingerprint and derivation path for every "
              "input, then bring it back.");
    } else if (!summary_.inputs.empty() &&
               summary_.inputsWithDerivation < summary_.inputs.size()) {
        add(Severity::Warning,
            std::to_string(summary_.inputs.size() - summary_.inputsWithDerivation) +
            " of " + std::to_string(summary_.inputs.size()) + " input(s) carry no "
            "BIP32 derivation path, so no key can be matched to them. They will be "
            "left unsigned and another signer will have to complete them.");
    }

    // Fee sanity. Both directions matter: an absurd fee is theft, and a
    // zero fee will simply never confirm.
    if (summary_.feeKnown) {
        if (summary_.feeSat == 0)
            add(Severity::Warning,
                "The fee is zero. This transaction will not be relayed or mined "
                "unless it is part of a package/CPFP arrangement.");

        if (summary_.totalInSat > 0) {
            const double pct = 100.0 * static_cast<double>(summary_.feeSat) /
                               static_cast<double>(summary_.totalInSat);
            if (pct >= 25.0) {
                char buf[160];
                std::snprintf(buf, sizeof(buf),
                    "The fee is %.1f%% of the total input value (%s sat). That is "
                    "extremely high - confirm it is intentional before signing.",
                    pct, formatSat(summary_.feeSat).c_str());
                add(Severity::Danger, buf);
            } else if (pct >= 5.0) {
                char buf[160];
                std::snprintf(buf, sizeof(buf),
                    "The fee is %.1f%% of the total input value.", pct);
                add(Severity::Warning, buf);
            }
        }

        if (summary_.feeRate > 1000.0)
            add(Severity::Danger,
                "The fee rate is above 1000 sat/vB. Fee rates that high are "
                "almost always a mistake or an attack.");
        else if (summary_.feeRate > 100.0)
            add(Severity::Warning, "The fee rate is above 100 sat/vB.");
        else if (summary_.feeRate > 0.0 && summary_.feeRate < 1.0)
            add(Severity::Warning,
                "The fee rate is below 1 sat/vB; this may never confirm.");
    }

    // Sighash flags. Anything other than SIGHASH_ALL changes what the signature
    // actually commits to, which is exactly the sort of thing a compromised
    // coordinator would slip in.
    for (std::size_t i = 0; i < summary_.inputs.size(); ++i) {
        const std::uint32_t sh = summary_.inputs[i].sighash;
        if (sh == 0 || sh == 0x01)
            continue;
        const bool anyoneCanPay = (sh & 0x80) != 0;
        const std::uint32_t base = sh & 0x1f;
        char shBuf[16];
        std::snprintf(shBuf, sizeof(shBuf), "0x%02x", sh & 0xffu);
        std::string detail = "Input " + std::to_string(i + 1) +
                             " requests sighash " + shBuf;
        if (base == 0x02)
            detail += " (NONE: the signature commits to no outputs at all)";
        else if (base == 0x03)
            detail += " (SINGLE: the signature commits to only one output)";
        if (anyoneCanPay)
            detail += " with ANYONECANPAY (other inputs can be added afterwards)";
        detail += ". Do not sign this unless you know exactly why it is needed.";
        add((anyoneCanPay || base != 0x01) ? Severity::Danger : Severity::Warning, detail);
    }

    // Existing signatures, non-standard scripts, taproot approximation.
    std::size_t withSigs = 0, nonStandard = 0, taproot = 0;
    for (const InputInfo &in : summary_.inputs) {
        if (in.existingSignatures > 0)
            ++withSigs;
        if (in.scriptType == "non-standard" || in.scriptType == "unknown")
            ++nonStandard;
        if (in.scriptType == "p2tr")
            ++taproot;
    }
    if (withSigs > 0)
        add(Severity::Info, std::to_string(withSigs) +
            " input(s) already carry a signature from another signer.");
    if (nonStandard > 0)
        add(Severity::Warning, std::to_string(nonStandard) +
            " input(s) spend a script SignerOS cannot decode into an address. "
            "The fee estimate for them is approximate.");
    if (taproot > 0)
        add(Severity::Info, std::to_string(taproot) +
            " taproot input(s): the size estimate assumes key-path spends.");

    if (summary_.locktime != 0)
        add(Severity::Info, "This transaction has locktime " +
            std::to_string(summary_.locktime) + ".");

    std::size_t rbf = 0;
    for (const InputInfo &in : summary_.inputs)
        if (in.sequence < 0xfffffffeu)
            ++rbf;
    if (rbf > 0)
        add(Severity::Info, std::to_string(rbf) +
            " input(s) signal replaceability (RBF) or a relative timelock.");

    // Change identification only works once a key is loaded, so this is
    // informational rather than a gate.
    if (masterKey().valid()) {
        if (summary_.signableInputs == 0)
            add(Severity::Danger,
                "None of the inputs can be signed with the key you entered. The "
                "derivation paths in this PSBT belong to a master key other than " +
                masterFingerprint() + ": a different wallet, a different "
                "passphrase, or the wrong network.");
        else if (summary_.signableInputs < summary_.inputs.size())
            add(Severity::Info, "You can sign " + std::to_string(summary_.signableInputs) +
                " of " + std::to_string(summary_.inputs.size()) +
                " inputs; the rest belong to other signers.");

        // A claim on our master that does not survive derivation. Either the
        // creating wallet is broken, or someone built a PSBT designed to make
        // this screen call an address of theirs "your change". There is no
        // reading of it under which signing is the right thing to do.
        std::size_t mismatched = 0, unverifiable = 0, verifiedChange = 0;
        for (std::size_t i = 0; i < summary_.outputs.size(); ++i) {
            const OutputInfo &out = summary_.outputs[i];
            switch (out.ownership) {
            case OutputOwnership::Mismatch:
                ++mismatched;
                block("an output claims to be your change but is not",
                      "Output " + std::to_string(i + 1) + " (" + out.address +
                      ") carries a derivation path for THIS wallet (" +
                      out.claimedFingerprint + " " + out.derivation + "), but the key "
                      "that path produces does not control that address. The file is "
                      "describing money as change that would not come back to you. "
                      "Signing is blocked.");
                break;
            case OutputOwnership::Unverifiable:
                ++unverifiable;
                add(Severity::Warning,
                    "Output " + std::to_string(i + 1) + " (" + out.address +
                    ") claims to be your change, but this PSBT does not include what "
                    "is needed to prove it (the script behind a multisig or taproot "
                    "output). Treat it as a payment out unless you know otherwise.");
                break;
            case OutputOwnership::Verified:
                ++verifiedChange;
                break;
            default:
                break;
            }
        }

        if (verifiedChange == 0 && summary_.outputs.size() > 1)
            add(Severity::Warning,
                "None of the outputs is verifiably your own change. If you expected "
                "change to come back to this wallet, stop and check the destination "
                "addresses.");

        // Verified change on an unexpected branch of our own wallet is not a
        // theft, but it is the shape of a misconfigured wallet, and money that
        // lands somewhere the operator is not watching is money they will
        // report as missing.
        std::vector<std::string> inputAccounts;
        for (const InputInfo &in : summary_.inputs) {
            if (!in.canSign || in.derivation.empty())
                continue;
            const std::string acct = pathAccountPrefix(in.derivation);
            if (!acct.empty() &&
                std::find(inputAccounts.begin(), inputAccounts.end(), acct) == inputAccounts.end())
                inputAccounts.push_back(acct);
        }

        for (std::size_t i = 0; i < summary_.outputs.size(); ++i) {
            const OutputInfo &out = summary_.outputs[i];
            if (out.ownership != OutputOwnership::Verified || out.derivation.empty())
                continue;

            const std::string chain = pathChainElement(out.derivation);
            if (!chain.empty() && chain != "0" && chain != "1")
                add(Severity::Warning,
                    "Output " + std::to_string(i + 1) + " is your key, but on branch " +
                    chain + " of " + out.derivation + " rather than the usual receive (0) "
                    "or change (1) branch.");

            const std::string acct = pathAccountPrefix(out.derivation);
            if (!acct.empty() && !inputAccounts.empty() &&
                std::find(inputAccounts.begin(), inputAccounts.end(), acct) == inputAccounts.end())
                add(Severity::Warning,
                    "Output " + std::to_string(i + 1) + " returns " +
                    formatBtc(out.amountSat) + " BTC to account " + acct +
                    " of this seed, while the coins are being spent from " +
                    inputAccounts.front() + ". It is still your money, but it will "
                    "not appear in the wallet you spent from.");
        }
    }
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

bool PsbtEngine::setKeyFromMnemonic(const SecureString &mnemonic,
                                    const SecureString &passphrase,
                                    std::string *err)
{
    clearKey();

    if (!bip39Validate(mnemonic, err))
        return false;

    // The BIP39 seed: 64 bytes, on the stack, in a locked buffer, wiped when
    // this function returns whatever happens.
    SecureBuffer<BIP39_SEED_LEN_512> seed;
    if (bip39_mnemonic_to_seed512(mnemonic.c_str(),
                                  passphrase.empty() ? nullptr : passphrase.c_str(),
                                  seed.data(), seed.capacity()) != WALLY_OK) {
        if (err) *err = "could not derive a seed from that mnemonic";
        return false;
    }
    seed.setSize(seed.capacity());

    SecureObject<ext_key> &master = masterKey();
    if (bip32_key_from_seed(seed.data(), seed.size(),
                            networkBip32Version(network_, true), 0,
                            master.get()) != WALLY_OK) {
        master.clear();
        if (err) *err = "could not derive the BIP32 master key from the seed";
        return false;
    }
    master.markValid();

    // seed's destructor wipes it here.
    if (psbt_ != nullptr)
        resummarise();
    return true;
}

bool PsbtEngine::setKeyFromXprv(const SecureString &xprv, std::string *err)
{
    clearKey();

    SecureObject<ext_key> &master = masterKey();
    if (bip32_key_from_base58(xprv.c_str(), master.get()) != WALLY_OK) {
        master.clear();
        if (err)
            *err = "that is not a valid extended private key (xprv/tprv). "
                   "Check for a transcription error.";
        return false;
    }

    // A public-only key cannot sign, and silently producing zero signatures is
    // a bad failure mode.
    if (master.get()->priv_key[0] != BIP32_FLAG_KEY_PRIVATE) {
        master.clear();
        if (err)
            *err = "that is an extended *public* key. Signing needs the private "
                   "key (xprv/tprv) or the mnemonic.";
        return false;
    }

    master.markValid();
    if (psbt_ != nullptr)
        resummarise();
    return true;
}

void PsbtEngine::clearKey()
{
    masterKey().clear();
    for (InputInfo &in : summary_.inputs)
        in.canSign = false;

    // Back to what the file claims and nothing more. Leaving a stale Verified
    // behind would let a label outlive the key that earned it.
    for (OutputInfo &out : summary_.outputs) {
        out.ownership = out.claimedFingerprint.empty() ? OutputOwnership::ThirdParty
                                                       : OutputOwnership::Claimed;
    }
    summary_.signableInputs = 0;
    summary_.verifiedChangeSat = 0;
    summary_.leavingSat = summary_.totalOutSat;
    summary_.ownershipChecked = false;
}

bool PsbtEngine::hasKey() const
{
    return masterKey().valid();
}

std::string PsbtEngine::masterFingerprint() const
{
    SecureObject<ext_key> &master = masterKey();
    if (!master.valid())
        return {};
    unsigned char fp[kFingerprintLen] = {};
    if (bip32_key_get_fingerprint(master.get(), fp, sizeof(fp)) != WALLY_OK)
        return {};
    return hexOf(fp, sizeof(fp));
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

bool PsbtEngine::sign(std::size_t *signaturesAdded, std::string *err)
{
    if (signaturesAdded)
        *signaturesAdded = 0;

    if (psbt_ == nullptr) {
        if (err) *err = "no PSBT is loaded";
        return false;
    }
    if (!masterKey().valid()) {
        if (err) *err = "no signing key has been entered";
        return false;
    }
    if (!summary_.safeToSign) {
        if (err)
            *err = "refusing to sign: " + (summary_.blockReason.empty()
                       ? std::string("this PSBT failed the safety checks")
                       : summary_.blockReason);
        return false;
    }
    if (summary_.signableInputs == 0) {
        if (err)
            *err = "none of the inputs can be signed with this key, so there is "
                   "nothing to do";
        return false;
    }

    std::size_t before = 0;
    for (std::size_t i = 0; i < psbt_->num_inputs; ++i)
        before += psbt_->inputs[i].signatures.num_items;

    // BIP174 simple signer, over every input whose BIP32 derivation matches our
    // master fingerprint. EC_FLAG_GRIND_R makes libwally grind for a low-R
    // signature: 71-byte DER instead of 72, deterministic, and it makes the
    // resulting transaction size predictable. Nonces are RFC6979-derived, so
    // signing the same input with the same key twice yields the same signature
    // and no entropy is required.
    const int rc = wally_psbt_sign_bip32(psbt_, masterKey().get(), EC_FLAG_GRIND_R);
    if (rc != WALLY_OK) {
        if (err)
            *err = "libwally rejected the signing operation (error " +
                   std::to_string(rc) + ")";
        return false;
    }

    std::size_t after = 0;
    for (std::size_t i = 0; i < psbt_->num_inputs; ++i)
        after += psbt_->inputs[i].signatures.num_items;

    if (after <= before) {
        if (err)
            *err = "no signature was added. The key derives to public keys that "
                   "do not appear in this PSBT's derivation paths.";
        return false;
    }

    if (signaturesAdded)
        *signaturesAdded = after - before;

    resummarise();
    return true;
}

std::string PsbtEngine::proposedResultName(const std::string &dir) const
{
    return freeFileName(dir, "signed_" + fileTimestamp(), ".psbt");
}

bool PsbtEngine::writeResult(const std::string &dir, const std::string &fileName,
                             bool alsoFinalTx,
                             std::string *psbtPath, std::string *txPath,
                             std::string *err)
{
    if (psbt_ == nullptr) {
        if (err) *err = "no PSBT is loaded";
        return false;
    }

    // Asked only for the warning at the end: the name itself now comes from the
    // operator, but a machine with no clock still proposed one built from
    // uptime and that is worth saying.
    bool clockUnset = false;
    fileTimestamp(&clockUnset);

    // What the operator left on the save-as step, put through the same rules
    // whatever the screen did with it. An empty or unusable name is not a
    // reason to refuse to save a signature that has already been made, so it
    // falls back to the name that step proposed.
    std::string name = sanitiseFileName(fileName, ".psbt");
    if (name.empty())
        name = proposedResultName(dir);

    auto writeFile = [&](const std::string &path, const char *data, std::size_t len) {
        // O_EXCL: never silently overwrite a previous signing result.
        const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0)
            return false;
        std::size_t done = 0;
        while (done < len) {
            const ssize_t n = ::write(fd, data + done, len - done);
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                ::close(fd);
                return false;
            }
            done += static_cast<std::size_t>(n);
        }
        // The mount is `sync`, but fsync makes the guarantee explicit: when this
        // returns, pulling the stick cannot lose the signature.
        const bool ok = (::fsync(fd) == 0);
        ::close(fd);
        return ok;
    };

    char *b64 = nullptr;
    if (wally_psbt_to_base64(psbt_, 0, &b64) != WALLY_OK || b64 == nullptr) {
        if (err) *err = "could not serialise the signed PSBT";
        return false;
    }
    std::string payload(b64);
    wally_free_string(b64);
    payload += '\n';

    const std::string outPath = dir + "/" + name;

    // Named by the operator, so a name already in use is reported rather than
    // stepped past: "-2" appearing on the end of a file somebody meant to
    // recognise is exactly the confusion the save-as step removes.
    if (::access(outPath.c_str(), F_OK) == 0) {
        if (err)
            *err = name + " already exists on the stick. Choose another name.";
        return false;
    }

    if (!writeFile(outPath, payload.data(), payload.size())) {
        if (err)
            *err = "could not write " + outPath +
                   ". Is the data partition present and writable?";
        return false;
    }
    if (psbtPath)
        *psbtPath = outPath;

    if (clockUnset)
        summary_.findings.push_back({ Severity::Info,
            "The hardware clock is not set, so the name offered for this file "
            "was built from uptime rather than a date." });

    // Optional: a broadcast-ready transaction, but only if this PSBT is now
    // complete. Finalisation happens on a clone so the PSBT we hold - and may
    // still write again - is never mutated.
    if (alsoFinalTx) {
        wally_psbt *clone = nullptr;
        if (wally_psbt_clone_alloc(psbt_, 0, &clone) == WALLY_OK && clone != nullptr) {
            std::size_t done = 0;
            if (wally_psbt_finalize(clone, 0) == WALLY_OK &&
                wally_psbt_is_finalized(clone, &done) == WALLY_OK && done != 0) {
                wally_tx *tx = nullptr;
                if (wally_psbt_extract(clone, WALLY_PSBT_EXTRACT_FINAL, &tx) == WALLY_OK &&
                    tx != nullptr) {
                    char *hex = nullptr;
                    if (wally_tx_to_hex(tx, WALLY_TX_FLAG_USE_WITNESS, &hex) == WALLY_OK &&
                        hex != nullptr) {
                        std::string txHex(hex);
                        wally_free_string(hex);
                        txHex += '\n';
                        // The same name the operator chose, with the extension
                        // swapped: the pair belongs together and reads as a
                        // pair in a file listing.
                        std::string stem = name;
                        if (stem.size() > 5 &&
                            stem.compare(stem.size() - 5, 5, ".psbt") == 0)
                            stem.erase(stem.size() - 5);
                        const std::string p = dir + "/" + stem + ".tx";
                        if (::access(p.c_str(), F_OK) != 0 &&
                            writeFile(p, txHex.data(), txHex.size()) && txPath)
                            *txPath = p;
                    }
                    wally_tx_free(tx);
                }
            }
            wally_psbt_free(clone);
        }
    }

    return true;
}

} // namespace signeros
