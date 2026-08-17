// SPDX-License-Identifier: MIT

#include "wallet_export.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>

#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_bip39.h>
#include <wally_core.h>
#include <wally_descriptor.h>
#include <wally_script.h>

namespace signeros {
namespace {

constexpr std::size_t kFingerprintLen = 4;
constexpr std::uint32_t kHardened = 0x80000000u;

std::string hexOf(const unsigned char *bytes, std::size_t len)
{
    static const char *digits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(digits[(bytes[i] >> 4) & 0x0f]);
        out.push_back(digits[bytes[i] & 0x0f]);
    }
    return out;
}

std::uint32_t coinType(Network n)
{
    // SLIP44: 0 for mainnet, 1 for every test chain. Signet and regtest share
    // testnet's coin type, which is what every wallet in this ecosystem does.
    return (n == Network::Mainnet) ? 0u : 1u;
}

// The network identifier, for the calls that take one (descriptor parsing,
// wally_scriptpubkey_to_address).
std::uint32_t addressNetwork(Network n)
{
    switch (n) {
    case Network::Mainnet: return WALLY_NETWORK_BITCOIN_MAINNET;
    case Network::Regtest: return WALLY_NETWORK_BITCOIN_REGTEST;
    case Network::Testnet:
    case Network::Signet:
    default:               return WALLY_NETWORK_BITCOIN_TESTNET;
    }
}

// The raw base58 prefix byte, which is a DIFFERENT thing that libwally also
// calls "version". wally_bip32_key_to_address() takes this one, and handing it
// a network identifier instead is silently accepted: it produces a
// well-formed, checksummed address with the wrong prefix - one that no wallet
// recognises and that no coin sent to it could ever be spent from. Caught by
// diffing against scripts/make_test_data.py, which is exactly what that file
// is for.
std::uint32_t p2pkhVersion(Network n)
{
    return (n == Network::Mainnet) ? WALLY_ADDRESS_VERSION_P2PKH_MAINNET
                                   : WALLY_ADDRESS_VERSION_P2PKH_TESTNET;
}

std::uint32_t p2shVersion(Network n)
{
    return (n == Network::Mainnet) ? WALLY_ADDRESS_VERSION_P2SH_MAINNET
                                   : WALLY_ADDRESS_VERSION_P2SH_TESTNET;
}

const char *bech32Hrp(Network n)
{
    switch (n) {
    case Network::Mainnet: return "bc";
    case Network::Regtest: return "bcrt";
    case Network::Testnet:
    case Network::Signet:
    default:               return "tb";
    }
}

std::uint32_t bip32PublicVersion(Network n)
{
    return (n == Network::Mainnet) ? BIP32_VER_MAIN_PUBLIC : BIP32_VER_TEST_PUBLIC;
}

// The four script types this device exports, in the order a person should
// prefer them today.
struct Standard {
    std::uint32_t purpose;
    const char *name;
    const char *label;
    const char *hintMainnet;
    const char *hintTestnet;
    const char *descriptorOpen;    // text before the key expression
    const char *descriptorClose;   // text after it
};

const Standard kStandards[] = {
    { 84, "BIP84", "Native SegWit (P2WPKH)",
      "addresses start bc1q", "addresses start tb1q",
      "wpkh(", ")" },
    { 86, "BIP86", "Taproot (P2TR)",
      "addresses start bc1p", "addresses start tb1p",
      "tr(", ")" },
    { 49, "BIP49", "Nested SegWit (P2SH-P2WPKH)",
      "addresses start 3", "addresses start 2",
      "sh(wpkh(", "))" },
    { 44, "BIP44", "Legacy (P2PKH)",
      "addresses start 1", "addresses start m or n",
      "pkh(", ")" },
};

// The multisig script types this device exports a cosigner key for, under
// BIP48's m/48'/<coin>'/<account>'/<script type>'.
//
// 2' first: every coordinator that can build a multisig today defaults to it.
// 1' costs two lines and is what an older wallet asks for. 3' (taproot
// multisig) is deliberately absent - there is no agreement yet on what it
// means, and a key exported under a path the ecosystem later redefines is a key
// the operator will have to work out how to move.
struct MultisigStandard {
    std::uint32_t scriptType;
    const char *name;
    const char *label;
};

const MultisigStandard kCosignerStandards[] = {
    { 2, "BIP48/2h", "Native SegWit multisig (P2WSH)" },
    { 1, "BIP48/1h", "Nested SegWit multisig (P2SH-P2WSH)" },
};

// ---------------------------------------------------------------------------

// The first receive address of an account, derived from the account key at
// .../0/0. Public derivation only: `account` has already had its private half
// stripped by the caller.
std::string firstAddressOf(const ext_key *accountPub, std::uint32_t purpose,
                           Network network)
{
    const std::uint32_t path[2] = { 0, 0 };
    ext_key child {};
    if (bip32_key_from_parent_path(accountPub, path, 2,
                                   BIP32_FLAG_KEY_PUBLIC, &child) != WALLY_OK)
        return {};

    char *addr = nullptr;
    std::string out;

    switch (purpose) {
    case 44:
        if (wally_bip32_key_to_address(&child, WALLY_ADDRESS_TYPE_P2PKH,
                                       p2pkhVersion(network), &addr) == WALLY_OK)
            out = addr;
        break;
    case 49:
        if (wally_bip32_key_to_address(&child, WALLY_ADDRESS_TYPE_P2SH_P2WPKH,
                                       p2shVersion(network), &addr) == WALLY_OK)
            out = addr;
        break;
    case 84:
        if (wally_bip32_key_to_addr_segwit(&child, bech32Hrp(network), 0,
                                           &addr) == WALLY_OK)
            out = addr;
        break;
    case 86: {
        // No bip32-to-taproot-address helper exists: build the scriptPubKey,
        // which applies the BIP341 tweak to the compressed key, then encode it.
        unsigned char script[WALLY_SCRIPTPUBKEY_P2TR_LEN] = {};
        std::size_t written = 0;
        if (wally_scriptpubkey_p2tr_from_bytes(child.pub_key, sizeof(child.pub_key),
                                               0, script, sizeof(script),
                                               &written) == WALLY_OK &&
            wally_addr_segwit_from_bytes(script, written, bech32Hrp(network), 0,
                                         &addr) == WALLY_OK)
            out = addr;
        break;
    }
    default:
        break;
    }

    if (addr != nullptr)
        wally_free_string(addr);
    // child is a public key: nothing secret, but it costs nothing to be tidy
    // and it keeps the habit uniform across this file.
    secureWipe(&child, sizeof(child));
    return out;
}

// Derives one account key, leaves its public half in `acct` and its base58
// spelling in `xpub`.
//
// Hardened steps need the private half, so it is derived into the caller's
// locked object - whose destructor wipes it - and stripped the moment the
// derivation is done. Nothing in this file ever hands back a private key.
bool deriveAccountPub(const ext_key *master, const std::uint32_t *path,
                      std::size_t pathLen, Network network,
                      SecureObject<ext_key> *acct, std::string *xpub)
{
    if (bip32_key_from_parent_path(master, path, pathLen, BIP32_FLAG_KEY_PRIVATE,
                                   acct->get()) != WALLY_OK)
        return false;
    if (bip32_key_strip_private_key(acct->get()) != WALLY_OK)
        return false;
    acct->get()->version = bip32PublicVersion(network);

    char *b58 = nullptr;
    if (bip32_key_to_base58(acct->get(), BIP32_FLAG_KEY_PUBLIC, &b58) != WALLY_OK ||
        b58 == nullptr)
        return false;
    *xpub = b58;
    wally_free_string(b58);
    return true;
}

// Appends libwally's BIP380 checksum to a descriptor, or returns it unchanged
// when libwally will not parse the expression.
//
// Unchanged, never guessed: a wrong checksum makes a correct descriptor look
// corrupt to every importer, which is a worse failure than an absent one (most
// importers accept a descriptor with no checksum at all).
std::string withChecksum(const std::string &descriptor, Network network)
{
    struct wally_descriptor *parsed = nullptr;
    if (wally_descriptor_parse(descriptor.c_str(), nullptr, addressNetwork(network),
                               0, &parsed) != WALLY_OK || parsed == nullptr)
        return descriptor;

    std::string out = descriptor;
    char *checksum = nullptr;
    if (wally_descriptor_get_checksum(parsed, 0, &checksum) == WALLY_OK &&
        checksum != nullptr) {
        out += "#";
        out += checksum;
        wally_free_string(checksum);
    }
    wally_descriptor_free(parsed);
    return out;
}

} // namespace

// ---------------------------------------------------------------------------

std::size_t entropyBytesForWords(std::size_t words)
{
    switch (words) {
    case 12: return BIP39_ENTROPY_LEN_128;
    case 15: return BIP39_ENTROPY_LEN_160;
    case 18: return BIP39_ENTROPY_LEN_192;
    case 21: return BIP39_ENTROPY_LEN_224;
    case 24: return BIP39_ENTROPY_LEN_256;
    default: return 0;
    }
}

bool isValidWordCount(std::size_t words)
{
    return entropyBytesForWords(words) != 0;
}

bool mnemonicFromEntropy(const unsigned char *entropy, std::size_t len,
                         SecureString *out, std::string *err)
{
    if (out == nullptr || entropy == nullptr) {
        if (err) *err = "internal error: no destination for the mnemonic";
        return false;
    }
    out->clear();

    struct words *wl = nullptr;
    if (bip39_get_wordlist(nullptr, &wl) != WALLY_OK || wl == nullptr) {
        if (err) *err = "the BIP39 wordlist is unavailable";
        return false;
    }

    char *text = nullptr;
    if (bip39_mnemonic_from_bytes(wl, entropy, len, &text) != WALLY_OK ||
        text == nullptr) {
        if (err) *err = "could not turn that entropy into a BIP39 mnemonic";
        return false;
    }

    const std::size_t textLen = std::strlen(text);
    const bool copied = out->assign(text, textLen);

    // wally_free_string() zeroes before freeing. This is the only moment the
    // mnemonic exists on the heap, and it ends here.
    wally_free_string(text);

    if (!copied) {
        out->clear();
        if (err) *err = "the generated mnemonic did not fit the secure buffer";
        return false;
    }

    // Never hand back something the signer would later refuse: the checksum
    // libwally just computed is verified with the same validator the signing
    // path uses.
    if (!bip39Validate(*out, err)) {
        out->clear();
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------

bool buildWalletExport(const SecureString &mnemonic,
                       const SecureString &passphrase,
                       Network network,
                       std::uint32_t account,
                       WalletExport *out,
                       std::string *err)
{
    if (out == nullptr) {
        if (err) *err = "internal error: no destination for the export";
        return false;
    }
    *out = WalletExport();
    out->network = network;
    out->account = account;
    out->passphraseUsed = !passphrase.empty();

    if (!bip39Validate(mnemonic, err))
        return false;

    SecureObject<ext_key> &master = processMasterKey();
    master.clear();

    // Everything from here to the end of the function holds private key
    // material. The single exit path below clears it; there is no early return
    // after this point that skips it.
    bool ok = false;
    do {
        {
            SecureBuffer<BIP39_SEED_LEN_512> seed;
            if (bip39_mnemonic_to_seed512(mnemonic.c_str(),
                                          passphrase.empty() ? nullptr
                                                             : passphrase.c_str(),
                                          seed.data(), seed.capacity()) != WALLY_OK) {
                if (err) *err = "could not derive a seed from that mnemonic";
                break;
            }
            if (bip32_key_from_seed(seed.data(), seed.capacity(),
                                    (network == Network::Mainnet)
                                        ? BIP32_VER_MAIN_PRIVATE
                                        : BIP32_VER_TEST_PRIVATE,
                                    0, master.get()) != WALLY_OK) {
                if (err) *err = "could not derive the BIP32 master key from the seed";
                break;
            }
            master.markValid();
            // seed is wiped here by its destructor.
        }

        {
            unsigned char fp[kFingerprintLen] = {};
            if (bip32_key_get_fingerprint(master.get(), fp, sizeof(fp)) != WALLY_OK) {
                if (err) *err = "could not compute the master fingerprint";
                break;
            }
            out->fingerprint = hexOf(fp, sizeof(fp));
        }

        const std::uint32_t coin = coinType(network);
        bool allDerived = true;

        for (const Standard &std_ : kStandards) {
            const std::uint32_t path[3] = {
                std_.purpose | kHardened,
                coin | kHardened,
                account | kHardened,
            };

            SecureObject<ext_key> acct;
            AccountExport ae;
            if (!deriveAccountPub(master.get(), path, 3, network, &acct, &ae.xpub)) {
                allDerived = false;
                break;
            }

            ae.standard = std_.name;
            ae.label = std_.label;
            ae.addressHint = (network == Network::Mainnet) ? std_.hintMainnet
                                                           : std_.hintTestnet;

            char pathBuf[64];
            std::snprintf(pathBuf, sizeof(pathBuf), "m/%u'/%u'/%u'",
                          std_.purpose, coin, account);
            ae.path = pathBuf;
            // Descriptors spell hardened steps with `h` (or `'`); `h` avoids a
            // quoting hazard in every shell and config file this text may pass
            // through on the way to a coordinator.
            std::snprintf(pathBuf, sizeof(pathBuf), "%uh/%uh/%uh",
                          std_.purpose, coin, account);
            ae.pathHardened = pathBuf;

            const std::string origin =
                "[" + out->fingerprint + "/" + ae.pathHardened + "]" + ae.xpub;

            ae.descriptor = withChecksum(
                std::string(std_.descriptorOpen) + origin + "/<0;1>/*" +
                    std_.descriptorClose, network);
            ae.receiveDescriptor = withChecksum(
                std::string(std_.descriptorOpen) + origin + "/0/*" +
                    std_.descriptorClose, network);
            ae.changeDescriptor = withChecksum(
                std::string(std_.descriptorOpen) + origin + "/1/*" +
                    std_.descriptorClose, network);

            ae.firstAddress = firstAddressOf(acct.get(), std_.purpose, network);

            out->accounts.push_back(ae);
            // acct's destructor wipes it here.
        }

        // The multisig half. Same master, one level deeper, and no descriptor
        // or address to go with it - see CosignerKey in the header for why that
        // is a property of multisig rather than a gap here.
        for (const MultisigStandard &ms : kCosignerStandards) {
            if (!allDerived)
                break;

            const std::uint32_t path[4] = {
                48u | kHardened,
                coin | kHardened,
                account | kHardened,
                ms.scriptType | kHardened,
            };

            SecureObject<ext_key> acct;
            CosignerKey ck;
            if (!deriveAccountPub(master.get(), path, 4, network, &acct, &ck.xpub)) {
                allDerived = false;
                break;
            }

            ck.standard = ms.name;
            ck.label = ms.label;

            char pathBuf[64];
            std::snprintf(pathBuf, sizeof(pathBuf), "m/48'/%u'/%u'/%u'",
                          coin, account, ms.scriptType);
            ck.path = pathBuf;
            std::snprintf(pathBuf, sizeof(pathBuf), "48h/%uh/%uh/%uh",
                          coin, account, ms.scriptType);
            ck.pathHardened = pathBuf;

            ck.keyOrigin = "[" + out->fingerprint + "/" + ck.pathHardened + "]" + ck.xpub;

            out->cosigners.push_back(ck);
        }

        if (!allDerived || out->accounts.empty() || out->cosigners.empty()) {
            if (err) *err = "the account keys could not be derived from this seed";
            out->accounts.clear();
            out->cosigners.clear();
            break;
        }

        ok = true;
    } while (false);

    // The private key goes now, whatever happened. Creating a wallet must not
    // leave a signing key resident: the next thing the operator sees is a
    // screen telling them nothing was kept, and that has to be true.
    master.clear();

    if (!ok)
        *out = WalletExport();
    return ok;
}

// ---------------------------------------------------------------------------

std::string renderWalletExport(const WalletExport &we, const std::string &createdAt)
{
    std::string s;
    s.reserve(4096);

    s += "# SignerOS watch-only export\n";
    s += "#\n";
    s += "# PUBLIC KEYS ONLY. Everything in this file can watch this wallet and\n";
    s += "# build transactions for it. Nothing in it can spend: there is no\n";
    s += "# private key, no seed and no mnemonic here, and this device never\n";
    s += "# wrote one anywhere. The only copy of the recovery words is the one\n";
    s += "# you wrote down by hand.\n";
    s += "#\n";
    s += "# Anyone who reads this file learns every address this wallet will\n";
    s += "# ever use, and its whole balance and history. Treat it as private,\n";
    s += "# not as secret.\n";
    s += "#\n";
    s += "# created            " + createdAt + "\n";
    s += "# master fingerprint " + we.fingerprint + "\n";
    s += "# network            " + std::string(networkName(we.network)) + "\n";
    s += "# account            " + std::to_string(we.account) + "\n";
    s += "# BIP39 passphrase   " +
         std::string(we.passphraseUsed
                         ? "yes - this export belongs to the passphrase you "
                           "entered. A different passphrase is a different wallet."
                         : "no") + "\n";
    s += "#\n";
    s += "# Every line below that does not start with # is meant to be copied into\n";
    s += "# a wallet: an output descriptor in the single-signature blocks, and a\n";
    s += "# cosigner key in the multisig block at the end. Pick the block for the\n";
    s += "# address type you want, then give your wallet either the single line or\n";
    s += "# the pair - whichever it accepts:\n";
    s += "#\n";
    s += "#   Sparrow          File -> Import Wallet -> Output Descriptor ->\n";
    s += "#                    Choose file, then pick a line. Takes the single\n";
    s += "#                    <0;1> line.\n";
    s += "#   Bitcoin Core     importdescriptors with \"active\": true\n";
    s += "#   Blockstream      wants the PAIR - one descriptor for receive and\n";
    s += "#   Green            one for change. The single <0;1> line will not\n";
    s += "#                    import; the two lines under it are the same keys\n";
    s += "#                    written the way it expects.\n";
    s += "#\n";
    s += "# Check the first address below matches what your wallet shows after\n";
    s += "# the import. If it does, the right file reached the right wallet.\n";
    s += "\n";

    for (const AccountExport &a : we.accounts) {
        s += "# ===========================================================\n";
        s += "# " + a.standard + "  -  " + a.label + "  (" + a.addressHint + ")\n";
        s += "#   derivation     " + a.path + "\n";
        s += "#   account xpub   " + a.xpub + "\n";
        s += "#   first address  " +
             (a.firstAddress.empty() ? std::string("(could not be derived)")
                                     : a.firstAddress) + "\n";
        s += "# ===========================================================\n";
        s += "#   receive and change in one line:\n";
        s += a.descriptor + "\n";
        s += "\n";
        // Bare rather than commented out. They were comments until a watch-only
        // import into Blockstream Green failed for want of them: its descriptor
        // path takes one expression per chain and does not parse the <0;1> form
        // at all, so the only lines in this file it could have used were the two
        // the file hid behind a '#'. Nothing reads this format automatically -
        // the header tells a person which line to pick - so the cost of the
        // extra lines is length, and the cost of hiding them was an export that
        // looked complete and was not.
        s += "#   the same keys as two lines, for wallets that want the chains\n";
        s += "#   separately (Blockstream Green): receive first, then change.\n";
        s += a.receiveDescriptor + "\n";
        s += a.changeDescriptor + "\n";
        s += "\n";
    }

    // The multisig block goes last, and says what it is before it says
    // anything else. Most people who create a wallet on this machine will never
    // build a multisig, and a section they cannot use must not read like a
    // section they failed to use.
    if (!we.cosigners.empty()) {
        s += "# ===========================================================\n";
        s += "# MULTISIG COSIGNER KEYS (BIP48)\n";
        s += "#\n";
        s += "# Only useful if this seed is one of several keys in a multisig\n";
        s += "# wallet. Setting up an ordinary single-signature wallet? Then you\n";
        s += "# are done above, and nothing below this line concerns you.\n";
        s += "#\n";
        s += "# There is no descriptor and no address here, and that is not a\n";
        s += "# failure: a multisig wallet does not exist until every cosigner's\n";
        s += "# key is known, and this device knows only its own. Give the key\n";
        s += "# line to your coordinator - Sparrow: Keystore -> Airgapped\n";
        s += "# Hardware Wallet -> xPub / Watch Only, and the same in Nunchuk,\n";
        s += "# Specter or Bitcoin Core - once for this signer and once for each\n";
        s += "# of the others. The coordinator builds the descriptor from all of\n";
        s += "# them; the resulting wallet file is what you keep, and it is what\n";
        s += "# you need to recover, alongside your words.\n";
        s += "#\n";
        s += "# The first-address check used above does not exist here, because\n";
        s += "# a single key has no address. What you compare in the coordinator\n";
        s += "# instead is the master fingerprint and the derivation path: both\n";
        s += "# are shown next to each cosigner once it is added.\n";
        s += "#\n";
        s += "# Take the 2h block unless a wallet asks you for the other one.\n";
        s += "# When this device is later asked to sign for that wallet, it can\n";
        s += "# only show an output as change if the PSBT carries the multisig\n";
        s += "# script itself - every coordinator listed above includes it.\n";
        s += "\n";

        for (const CosignerKey &c : we.cosigners) {
            s += "# ===========================================================\n";
            s += "# " + c.standard + "  -  " + c.label + "\n";
            s += "#   derivation     " + c.path + "\n";
            s += "#   account xpub   " + c.xpub + "\n";
            s += "# ===========================================================\n";
            s += "#   the same key with its origin, which is what a coordinator\n";
            s += "#   asks for - fingerprint, path and key in one line:\n";
            s += c.keyOrigin + "\n";
            s += "\n";
        }
    }

    s += "# end of export\n";
    return s;
}

std::string proposedWalletExportName(const WalletExport &we, const std::string &dir)
{
    return freeFileName(dir, "signeros-" + we.fingerprint + "-" + fileTimestamp(),
                        ".descriptors.txt");
}

bool writeWalletExport(const WalletExport &we, const std::string &dir,
                       const std::string &fileName,
                       std::string *pathOut, std::string *err)
{
    if (we.accounts.empty()) {
        if (err) *err = "there is nothing to export";
        return false;
    }

    // The timestamp still goes *inside* the file as its "created" line, whatever
    // the operator called it: the name is theirs, the provenance is not.
    const std::string payload = renderWalletExport(we, fileTimestamp());

    std::string name = sanitiseFileName(fileName, ".txt");
    if (name.empty())
        name = proposedWalletExportName(we, dir);
    const std::string path = dir + "/" + name;

    // O_EXCL: a second export never silently replaces the first. Since the name
    // came from the operator, the collision is reported to them rather than
    // worked around with a suffix they did not ask for.
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) {
        if (err)
            *err = (errno == EEXIST)
                       ? name + " already exists on the stick. Choose another name."
                       : "could not create " + path +
                             ". Is the data partition present and writable?";
        return false;
    }

    std::size_t done = 0;
    bool ok = true;
    while (done < payload.size()) {
        const ssize_t n = ::write(fd, payload.data() + done, payload.size() - done);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            ok = false;
            break;
        }
        done += static_cast<std::size_t>(n);
    }
    // The mount is `sync`, but fsync makes the guarantee explicit: when this
    // returns, pulling the stick cannot lose the export.
    if (ok && ::fsync(fd) != 0)
        ok = false;
    ::close(fd);

    if (!ok) {
        ::unlink(path.c_str());
        if (err) *err = "could not write " + path + " (the write failed part-way)";
        return false;
    }

    if (pathOut) *pathOut = path;
    return true;
}

} // namespace signeros
