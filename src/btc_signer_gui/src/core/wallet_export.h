// SPDX-License-Identifier: MIT
//
// wallet_export.h - creating a wallet, and the only artefact that ever leaves
// this machine when one is created.
//
// The rule this file exists to enforce, and the reason it is written as a
// separate translation unit rather than folded into psbt_engine:
//
//     NOTHING derived from the seed is ever written to any medium.
//
// Not the mnemonic, not the BIP39 seed, not an xprv, not a "recovery file", not
// a log line, not a temporary file. The wallet's private half exists only in
// locked RAM, for as long as the screen that created it is open, and is wiped
// on the way out. The single file that reaches the data partition contains
// extended PUBLIC keys and output descriptors: enough for Sparrow or any other
// coordinator to watch the wallet and build transactions, and not enough to
// spend a satoshi.
//
// A seed that exists in exactly one place - written on paper by the person who
// owns it - is the whole point of an air-gapped signer. A device that helpfully
// keeps a copy has thrown that away and become the weakest link in its own
// threat model.
//
// No Qt here: the derivation and the file format are exercised headless by
// scripts/host_selftest.sh, against the same fixture the signing path uses.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "psbt_engine.h"   // Network
#include "secure_memory.h"

namespace signeros {

// One script type's worth of the export: what Sparrow calls a wallet.
struct AccountExport {
    std::string standard;      // "BIP84"
    std::string label;         // "Native SegWit"
    std::string addressHint;   // "addresses start bc1q"
    std::string path;          // "m/84'/0'/0'"
    std::string pathHardened;  // "84h/0h/0h" - descriptor spelling
    std::string xpub;          // account-level extended PUBLIC key

    // The descriptor a coordinator imports. Receive and change in one
    // expression (`<0;1>`), plus the two separate ones for wallets that do not
    // understand multipath. Checksums are computed by libwally and are empty
    // when it declined to parse the expression, because a made-up checksum is
    // worse than none.
    std::string descriptor;
    std::string receiveDescriptor;
    std::string changeDescriptor;

    // The first receive address, m/<purpose>'/<coin>'/<account>'/0/0. Printed so
    // the operator can compare it with what their coordinator shows after the
    // import - a one-glance proof that the right file reached the right wallet.
    std::string firstAddress;
};

// This device's share of a multisig wallet: BIP48,
// m/48'/<coin>'/<account>'/<script type>'.
//
// A separate struct rather than a fifth entry in the AccountExport list,
// because two of the four things an AccountExport promises cannot exist here.
// A multisig wallet is not defined until every cosigner's key is known, and
// this machine knows exactly one of them - so there is no descriptor to write
// and no first address to compare, and an AccountExport with those fields empty
// would render as "(could not be derived)": a failure message for something
// that is not a failure.
//
// What a coordinator actually wants is the key with its origin attached, which
// is what `keyOrigin` is.
struct CosignerKey {
    std::string standard;      // "BIP48/2h" - no spaces: host_selftest.sh diffs
                               // these lines field by field
    std::string label;         // "Native SegWit multisig (P2WSH)"
    std::string path;          // "m/48'/0'/0'/2'"
    std::string pathHardened;  // "48h/0h/0h/2h" - descriptor spelling
    std::string xpub;          // account-level extended PUBLIC key

    // "[<fingerprint>/48h/0h/0h/2h]xpub..." - the one string a coordinator is
    // given per signer. Assembled here rather than by each reader of this
    // struct so there is one spelling of it in the process.
    std::string keyOrigin;
};

struct WalletExport {
    std::string fingerprint;      // master fingerprint, 8 lowercase hex digits
    Network network = Network::Mainnet;
    std::uint32_t account = 0;
    bool passphraseUsed = false;  // stated in the file: a different passphrase
                                  // is a different wallet, and people forget
    std::vector<AccountExport> accounts;
    std::vector<CosignerKey> cosigners;
};

// How many bytes of entropy a mnemonic of this many words encodes.
// 12->16, 15->20, 18->24, 21->28, 24->32. Returns 0 for an unsupported count.
std::size_t entropyBytesForWords(std::size_t words);

// True for a word count BIP39 defines.
bool isValidWordCount(std::size_t words);

// Turns raw entropy into a mnemonic, straight into a SecureString.
//
// libwally hands back a heap-allocated string; it is copied into `out` and the
// original is released with wally_free_string(), which zeroes it first. That is
// the only moment a mnemonic touches the heap in this process, and it is as
// short as the API allows.
bool mnemonicFromEntropy(const unsigned char *entropy, std::size_t len,
                         SecureString *out, std::string *err);

// Derives the watch-only export for a mnemonic + optional passphrase.
//
// Uses the process-wide master key slot (see processMasterKey) rather than
// opening a second place in the address space where a private key can live, and
// clears it before returning - success or failure. No private key survives this
// call.
bool buildWalletExport(const SecureString &mnemonic,
                       const SecureString &passphrase,
                       Network network,
                       std::uint32_t account,
                       WalletExport *out,
                       std::string *err);

// The exact bytes written to the data partition. Public data only; the
// self-test renders and inspects this without writing anything.
std::string renderWalletExport(const WalletExport &we, const std::string &createdAt);

// The name the save-as step offers: "signeros-<fingerprint>-<timestamp>
// .descriptors.txt", stepped past anything already in `dir`.
std::string proposedWalletExportName(const WalletExport &we, const std::string &dir);

// Writes the descriptor file to <dir>/<fileName> and fsyncs it.
//
// `fileName` is whatever the operator left on the save-as step; it goes through
// sanitiseFileName() here as well, and an empty one falls back to
// proposedWalletExportName(). Never overwrites: a name already in use is an
// error, because a file the operator named is one they mean to find again.
bool writeWalletExport(const WalletExport &we, const std::string &dir,
                       const std::string &fileName,
                       std::string *pathOut, std::string *err);

} // namespace signeros
