// SPDX-License-Identifier: MIT
//
// psbt_engine.h - BIP174/BIP370 parsing, human-readable inspection and
// BIP32/BIP39 signing, on top of libwally-core.
//
// Deliberately free of Qt: this is the part that touches key material and
// attacker-controlled files, so it is built and run standalone by
// scripts/host_selftest.sh and by the in-image --self-test mode. The GUI is a
// consumer of these structs, not a participant in signing.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "secure_memory.h"

struct wally_psbt;
struct wally_tx;
struct ext_key;

namespace signeros {

// ---------------------------------------------------------------------------
// The one and only place in this process where a BIP32 master private key can
// live: static storage, page-locked, wiped on clear.
//
// Declared here rather than kept private to psbt_engine.cpp because wallet
// creation (core/wallet_export.h) derives from a master key too. Giving it its
// own slot would double the number of page ranges that can hold a master
// private key, for no benefit - this device only ever has one key in hand at a
// time, and having exactly one address in the process where such a key can be
// is what makes "the key is gone" a statement that can be checked rather than
// hoped for.
//
// Callers clear it when they are done. PsbtEngine::clearKey() and
// buildWalletExport() both do.
// ---------------------------------------------------------------------------
SecureObject<ext_key> &processMasterKey();

// ---------------------------------------------------------------------------

enum class Network { Mainnet, Testnet, Signet, Regtest };

Network networkFromString(const std::string &s, bool *ok = nullptr);
const char *networkName(Network n);

// Formatting helpers shared by the GUI and the self-test so both render the
// same numbers the same way.
std::string formatBtc(std::uint64_t satoshi);          // "0.00123456"
std::string formatSat(std::uint64_t satoshi);          // "123 456"
std::string formatFeeRate(double satPerVbyte);         // "12.4"

// --- output file names -----------------------------------------------------
//
// Every file this machine writes is named by the operator: both writers show a
// default on a "save as" step and take back whatever the operator left there.
// The rules for what a name may be therefore live in one place rather than
// once per screen, and the two writers below apply them again on the way in -
// a UI that forgot to sanitise must not be able to write "../something".

// The timestamp the default names are built from: "20260811-190438", or
// "noclock-<uptime seconds>" when the RTC is unset, which the caller should
// say out loud rather than pass off as a date.
std::string fileTimestamp(bool *clockLooksUnset = nullptr);

// Reduces `name` to a single path component: no directory, no leading dot, only
// printable ASCII minus the characters FAT and the shell argue about, and
// `suffix` appended if it is not already there. Returns "" when nothing usable
// is left, which callers must treat as "ask again" rather than "use a default".
std::string sanitiseFileName(const std::string &name, const std::string &suffix);

// "<stem><suffix>" if that does not exist in `dir`, otherwise the first free
// "<stem>-2<suffix>", "<stem>-3<suffix>", ... Only ever used to *propose* a
// name: what the operator then types is written as typed, and a collision is
// reported rather than silently renamed.
std::string freeFileName(const std::string &dir, const std::string &stem,
                         const std::string &suffix);

// ---------------------------------------------------------------------------
// What the inspection screen shows. Everything here is derived from the PSBT
// alone; nothing requires a key.
// ---------------------------------------------------------------------------

struct InputInfo {
    std::string outpoint;        // <txid>:<vout>, txid in RPC byte order
    std::string address;         // decoded from the UTXO's scriptPubKey
    std::string scriptType;      // "p2wpkh", "p2sh-p2wpkh", "p2tr", ...
    std::string derivation;      // "m/84'/0'/0'/0/3" for our key, if present
    std::string fingerprint;     // master fingerprint the keypath belongs to
    std::uint64_t amountSat = 0;
    bool amountKnown = false;    // false when the PSBT carries no UTXO for it
    bool canSign = false;        // our key derives to a pubkey in its keypaths
    bool alreadyFinal = false;
    std::size_t existingSignatures = 0;
    std::uint32_t sequence = 0;
    std::uint32_t sighash = 0;   // 0 means "not specified" => SIGHASH_ALL
};

// How much this device knows about who an output pays.
//
// The distinction between "the file says so" and "we checked" is the entire
// point of this enum. A PSBT is attacker-controlled input: the master
// fingerprint and derivation path attached to an output are bytes its creator
// wrote, not a proof. A signer that paints an output green because those bytes
// look familiar can be told to paint the attacker's address green - the operator
// then reads "change coming back to you" and authorises the theft themselves.
//
// So only Verified means: the master key in this device derives a public key
// along the claimed path, and that public key reconstructs this output's
// scriptPubKey byte for byte.
enum class OutputOwnership {
    ThirdParty,    // no derivation information: a payment to someone else
    Claimed,       // a derivation is claimed but nothing is verified - either no
                   // key has been entered yet, or it names another master
    Verified,      // derived from our master, and it reproduces this script
    Unverifiable,  // claims our master over a script this device cannot
                   // reconstruct (a multisig whose script the PSBT omitted, a
                   // taproot output with a script tree)
    Mismatch,      // claims our master, and the key we derive does NOT produce
                   // this script: a broken creator at best, an attack at worst
};

const char *ownershipName(OutputOwnership o);

struct OutputInfo {
    std::string address;
    std::string scriptType;
    std::string derivation;          // the claimed path, when the PSBT carries one
    std::string claimedFingerprint;  // the master that path claims to belong to
    std::uint64_t amountSat = 0;
    OutputOwnership ownership = OutputOwnership::ThirdParty;
    bool isOpReturn = false;
    std::string opReturnHex;

    // The only test the user interface may colour green.
    bool isVerifiedChange() const { return ownership == OutputOwnership::Verified; }
};

enum class Severity { Info, Warning, Danger };

struct Finding {
    Severity severity = Severity::Info;
    std::string text;
};

struct TxSummary {
    std::uint32_t psbtVersion = 0;   // 0 = BIP174 v0, 2 = BIP370 v2
    std::uint32_t txVersion = 0;
    std::uint32_t locktime = 0;
    std::string txid;                // unsigned txid (v0) / BIP370 id (v2)

    std::vector<InputInfo> inputs;
    std::vector<OutputInfo> outputs;

    std::uint64_t totalInSat = 0;
    std::uint64_t totalOutSat = 0;
    std::uint64_t feeSat = 0;
    bool feeKnown = false;           // false if any input amount is missing

    // Verified change, and what is therefore actually leaving this wallet.
    // Both are zero until a key is entered: with nothing to verify against,
    // every output has to be assumed to be a payment out, which is the
    // conservative direction to be wrong in.
    std::uint64_t verifiedChangeSat = 0;
    std::uint64_t leavingSat = 0;    // totalOutSat - verifiedChangeSat
    bool ownershipChecked = false;   // a key is loaded, so the labels mean something

    std::size_t estimatedVsize = 0;  // includes estimated signatures
    double feeRate = 0.0;            // sat/vB, 0 when feeKnown is false

    std::size_t signableInputs = 0;

    // How many inputs say which key should sign them, i.e. carry BIP32
    // derivation information at all. This is knowable without a key, and it is
    // what separates "you used the wrong wallet" from "this file cannot be
    // signed by anybody".
    std::size_t inputsWithDerivation = 0;

    bool alreadyFinalised = false;

    std::vector<Finding> findings;

    // Hard gate for the signing screen. When false, `blockReason` says why and
    // the engine refuses to sign at all.
    bool safeToSign = false;
    std::string blockReason;
};

// ---------------------------------------------------------------------------
// PsbtEngine
//
// One PSBT and at most one key at a time. The master key lives in a single
// static, page-locked SecureObject (see psbt_engine.cpp) rather than in this
// object, so there is exactly one place in the address space where a master
// private key can ever be.
// ---------------------------------------------------------------------------
class PsbtEngine {
public:
    // Initialises libwally and blinds the secp256k1 context from
    // /dev/urandom. Call once per process.
    static bool initLibrary(std::string *err);
    static void shutdownLibrary();
    static std::string libraryVersion();

    explicit PsbtEngine(Network network);
    ~PsbtEngine();

    PsbtEngine(const PsbtEngine &) = delete;
    PsbtEngine &operator=(const PsbtEngine &) = delete;

    Network network() const { return network_; }
    void setNetwork(Network n) { network_ = n; }

    // --- loading ---------------------------------------------------------
    // Reads a .psbt file: raw BIP174 binary or base64, autodetected. Applies a
    // hard size cap before parsing, because this is attacker-controlled input
    // arriving on a removable disk.
    bool load(const std::string &path, std::string *err);
    void unload();
    bool isLoaded() const { return psbt_ != nullptr; }
    const std::string &sourcePath() const { return sourcePath_; }
    const std::string &sourceName() const { return sourceName_; }

    const TxSummary &summary() const { return summary_; }

    // --- key handling ----------------------------------------------------
    // Derives the BIP32 master from a BIP39 mnemonic (validated against the
    // wordlist) and an optional passphrase, then re-evaluates which inputs are
    // signable. The SecureStrings are not retained.
    bool setKeyFromMnemonic(const SecureString &mnemonic,
                            const SecureString &passphrase,
                            std::string *err);

    // Accepts an xprv/tprv as an alternative to a mnemonic.
    bool setKeyFromXprv(const SecureString &xprv, std::string *err);

    void clearKey();
    bool hasKey() const;
    std::string masterFingerprint() const;

    // --- signing ---------------------------------------------------------
    // BIP174 "simple signer": for every input whose BIP32 derivation path
    // matches our master, derive the child key and add a signature. Refuses
    // outright if summary().safeToSign is false.
    bool sign(std::size_t *signaturesAdded, std::string *err);

    // The name the signing screen offers on its "save as" step:
    // "signed_<timestamp>.psbt", stepped past anything already in `dir`.
    std::string proposedResultName(const std::string &dir) const;

    // Serialises the (partially) signed PSBT as base64 to <dir>/<fileName> and
    // fsyncs it. When alsoFinalTx is set and every input finalises,
    // additionally writes the same name with ".psbt" replaced by ".tx",
    // carrying the raw network transaction in hex.
    //
    // `fileName` is what the operator left on the save-as step; an empty one
    // falls back to proposedResultName(). It is sanitised here too, and a name
    // that already exists is an error rather than a silent rename: the whole
    // point of naming the file was to know which one it is.
    bool writeResult(const std::string &dir,
                     const std::string &fileName,
                     bool alsoFinalTx,
                     std::string *psbtPath,
                     std::string *txPath,
                     std::string *err);

private:
    bool parse(const unsigned char *data, std::size_t len, std::string *err);
    void resummarise();
    // Needs the extracted transaction: verifying an output means rebuilding its
    // scriptPubKey from a derived key and comparing it with the real one.
    void evaluateSignability(const wally_tx *tx);
    void deriveFindings();
    std::size_t estimateVsize(const wally_tx *unsignedTx) const;

    std::string addressForScript(const unsigned char *script, std::size_t len,
                                 std::string *typeOut) const;

    Network network_;
    wally_psbt *psbt_ = nullptr;
    std::string sourcePath_;
    std::string sourceName_;
    TxSummary summary_;

    // True when strict BIP174 parsing failed and the permissive parser was
    // used instead. Surfaced as a warning rather than hidden.
    bool looseParse_ = false;
};

// ---------------------------------------------------------------------------
// Directory scanning for the file-selection screen.
//
// Shared with the self-test so both agree on what counts as a candidate file.
// ---------------------------------------------------------------------------
struct PsbtFileEntry {
    std::string name;
    std::string path;
    std::uint64_t sizeBytes = 0;
    std::int64_t mtime = 0;
    // True for files this device produced (signed_*.psbt). Listed but sorted
    // last, so a second signer can pick one up while it stays obvious which
    // files are inputs and which are results.
    bool isSignerOutput = false;
};

// Lists *.psbt (case-insensitive) in `dir`, newest first within each group,
// signer outputs last. Never recurses: an untrusted stick is not a place to
// walk arbitrary directory trees.
std::vector<PsbtFileEntry> listPsbtFiles(const std::string &dir);

// ---------------------------------------------------------------------------
// BIP39 helpers used by the on-screen keyboard's word completion. The wordlist
// is public data, not a secret; the prefix passed in is a fragment of one, so
// callers wipe their own buffer afterwards.
// ---------------------------------------------------------------------------

// Appends up to maxResults BIP39 words starting with `prefix` to `out`.
void bip39Suggestions(const char *prefix,
                      std::size_t maxResults,
                      std::vector<std::string> *out);

// Validates the checksum and wordlist membership of a candidate mnemonic.
bool bip39Validate(const SecureString &mnemonic, std::string *err);

// Which cells of a mnemonic grid hold something that is not a BIP39 word.
//
// Bit i of the result is set when slot i (see SecureString's grid view) is
// non-empty and is not in the wordlist. Empty slots are not marked - they are
// unfinished, not wrong - and neither is `inProgressSlot`, which is the cell
// the cursor is standing in and is a prefix rather than a mistake. Pass -1 when
// no cell is being typed into.
//
// This exists because bip39Validate() can only ever say "somewhere in here is a
// word I do not know, or the checksum does not add up". On the import screen,
// where the device has no reference to compare against, that answer sends the
// operator back through twenty-four words by hand. One pass over the 2048-word
// list against every slot at once answers the useful question instead: which
// cell.
std::uint32_t bip39UnknownSlots(const SecureString &mnemonic, int inProgressSlot);

} // namespace signeros
