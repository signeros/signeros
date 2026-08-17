// SPDX-License-Identifier: MIT

#include "selftest.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// Only for the "no key is resident afterwards" assertion below: checking
// processMasterKey() means instantiating SecureObject<ext_key>, which needs the
// real struct rather than psbt_engine.h's forward declaration.
#include <wally_bip32.h>

#include "entropy.h"
#include "psbt_engine.h"
#include "secure_memory.h"
#include "wallet_export.h"

namespace signeros {
namespace {

void emit(const std::string &line)
{
    std::fputs(("SELFTEST: " + line + "\n").c_str(), stdout);
    std::fflush(stdout);
}

int fail(const std::string &reason)
{
    emit("FAIL " + reason);
    return 1;
}

// Reads the mnemonic file straight into a SecureString: it never lands in a
// std::string, so the only copy in this process is the locked, self-wiping one.
bool readMnemonicFile(const std::string &path, SecureString *out, std::string *err)
{
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (err) *err = "cannot open " + path;
        return false;
    }

    char buf[SecureString::kCapacity];
    const ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
    ::close(fd);

    if (n <= 0) {
        secureWipe(buf, sizeof(buf));
        if (err) *err = "cannot read " + path;
        return false;
    }

    out->clear();
    out->append(buf, static_cast<std::size_t>(n));
    secureWipe(buf, sizeof(buf));

    // Trailing newline from `echo` and friends.
    out->normaliseWhitespace();
    return !out->empty();
}

// ---------------------------------------------------------------------------
// Report whether this system can do networking at all.
//
// Everything else about guardrail 1 is checked at build time, against the
// generated kernel .config. This checks the running system: with CONFIG_NET=n
// there is no socket layer, so socket(2) is not merely blocked - the syscall is
// not implemented, and /proc/net does not exist.
//
// Reported rather than asserted, because this same code runs on a normal Linux
// build machine under scripts/host_selftest.sh where sockets obviously work.
// scripts/test_in_qemu.sh is what turns it into a hard requirement inside the
// appliance.
// ---------------------------------------------------------------------------
void reportNetworkAbsence()
{
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd >= 0) {
        ::close(fd);
        emit("socket-af-inet=AVAILABLE (this system has a network stack)");
    } else {
        emit("socket-af-inet=unavailable errno=" + std::to_string(errno) +
             (errno == ENOSYS ? " (ENOSYS: the syscall does not exist)" : ""));
    }

    struct stat st {};
    const bool procNet = (::stat("/proc/net", &st) == 0);
    emit(std::string("proc-net=") + (procNet ? "present" : "absent"));
}

// ---------------------------------------------------------------------------
// Wallet creation, headless.
//
// Two separate things are proved here, and neither of them can be proved from
// the GUI:
//
//   1. The derivation. Every account xpub and first address the export would
//      contain is printed, so scripts/host_selftest.sh can diff them against
//      scripts/make_test_data.py - a pure-stdlib implementation that shares no
//      code with libwally-core. A subtly wrong xpub is the worst failure this
//      feature has: the owner's coordinator would watch a wallet their seed
//      does not control, and nobody would find out until coins had been sent
//      to addresses that cannot be spent from.
//
//   2. The refusal to write a secret. The rendered file is scanned for the
//      mnemonic's own words and for anything that looks like an extended
//      private key. The design says nothing derived from the seed is ever
//      written; this is what stops that staying a promise.
//
// Runs before the signing key is set, because the master key slot is
// process-wide and buildWalletExport() clears it on the way out.
// ---------------------------------------------------------------------------
// `tag` is appended to every key this prints, so the same checks can be run for
// more than one account without the two sets of lines running together. The
// account is operator-selectable on the import screen, and an account index
// that derives wrongly fails in exactly the way this function exists to catch:
// a plausible file for a wallet the seed does not control.
bool runWalletChecks(Network net, const SecureString &mnemonic,
                     std::uint32_t account, const std::string &tag,
                     std::string *err)
{
    WalletExport we;
    SecureString noPassphrase;
    if (!buildWalletExport(mnemonic, noPassphrase, net, account, &we, err))
        return false;

    emit("wallet-fingerprint" + tag + "=" + we.fingerprint);
    for (const AccountExport &a : we.accounts) {
        emit("wallet-account" + tag + "=" + a.standard + " path=" + a.path +
             " xpub=" + a.xpub + " first=" + a.firstAddress);
        if (a.xpub.empty() || a.firstAddress.empty()) {
            if (err) *err = a.standard + " produced an empty xpub or address";
            return false;
        }
        emit("wallet-descriptor" + tag + "=" + a.descriptor);
    }

    // The BIP48 cosigner keys, diffed against the same independent
    // implementation. There is no address to print alongside them - a multisig
    // key has none on its own - so the origin string is checked here instead:
    // it is the whole of what a coordinator is given, and a fingerprint or a
    // path spelled wrongly in it produces a wallet that watches the right
    // addresses and cannot build a spendable transaction for them.
    for (const CosignerKey &c : we.cosigners) {
        emit("wallet-cosigner" + tag + "=" + c.standard + " path=" + c.path +
             " xpub=" + c.xpub);
        if (c.xpub.empty()) {
            if (err) *err = c.standard + " produced an empty xpub";
            return false;
        }
        if (c.keyOrigin != "[" + we.fingerprint + "/" + c.pathHardened + "]" + c.xpub) {
            if (err) *err = c.standard + " has a key origin that does not match "
                                         "its own fingerprint, path and key";
            return false;
        }
    }
    if (we.cosigners.empty()) {
        if (err) *err = "the export carries no multisig cosigner keys";
        return false;
    }

    // The master slot must be empty again: creating a wallet leaves no signing
    // key behind, and the screen that does it says so to the operator.
    if (processMasterKey().valid()) {
        if (err) *err = "a master private key was still resident after the export";
        return false;
    }

    const std::string rendered = renderWalletExport(we, "selftest");

    // No private material, checked rather than assumed. The word scan is the
    // blunt one and the important one: if any part of the mnemonic reached the
    // file, at least one of its words is in there.
    for (const char *marker : { "xprv", "tprv", "zprv", "vprv", "yprv", "uprv" }) {
        if (rendered.find(marker) != std::string::npos) {
            if (err) *err = std::string("the export text contains '") + marker + "'";
            return false;
        }
    }

    char word[32] = {};
    std::size_t wordLen = 0;
    const char *p = mnemonic.c_str();
    for (std::size_t i = 0; i <= mnemonic.size(); ++i) {
        const char c = p[i];
        if (c != ' ' && c != '\0') {
            if (wordLen + 1 < sizeof(word))
                word[wordLen++] = c;
            continue;
        }
        if (wordLen >= 3) {   // "the" and friends are not BIP39 words anyway
            word[wordLen] = '\0';
            if (rendered.find(word) != std::string::npos) {
                secureWipe(word, sizeof(word));
                if (err) *err = "the export text contains a word of the mnemonic";
                return false;
            }
        }
        secureWipe(word, sizeof(word));
        wordLen = 0;
    }
    emit("wallet-export-has-no-secrets" + tag + "=yes bytes=" +
         std::to_string(rendered.size()));

    return true;
}

// ---------------------------------------------------------------------------
// Output file names.
//
// Both writers take the name from the operator now (ui/save_as.h), which means
// a string typed on a screen decides what path is opened. sanitiseFileName() is
// what stands between that and the filesystem, so it is checked here rather
// than trusted: this runs on every `make host-test` and inside the booted
// image.
// ---------------------------------------------------------------------------
bool runFileNameChecks(std::string *err)
{
    auto bad = [&](const char *what) {
        if (err) *err = what;
        return false;
    };

    // The ordinary case: left alone, extension added when it is missing.
    if (sanitiseFileName("mywallet", ".txt") != "mywallet.txt")
        return bad("a plain name did not get the extension");
    if (sanitiseFileName("mywallet.txt", ".txt") != "mywallet.txt")
        return bad("an extension already present was doubled");
    if (sanitiseFileName("cold storage 2026", ".psbt") != "cold storage 2026.psbt")
        return bad("spaces inside a name were not kept");

    // Nothing may escape the directory it is written into.
    if (sanitiseFileName("../../etc/passwd", ".txt") != "passwd.txt")
        return bad("a relative path was not reduced to its last component");
    if (sanitiseFileName("/etc/passwd", ".txt") != "passwd.txt")
        return bad("an absolute path was not reduced to its last component");
    if (sanitiseFileName("..", ".txt") != "")
        return bad("\"..\" did not reduce to nothing");
    if (sanitiseFileName(".hidden", ".txt") != "hidden.txt")
        return bad("a leading dot was kept");

    // Characters that are a problem on FAT or in somebody's shell.
    if (sanitiseFileName("a*b?c|d", ".txt") != "abcd.txt")
        return bad("wildcard characters survived");
    if (sanitiseFileName(std::string("tab\there"), ".txt") != "tabhere.txt")
        return bad("a control character survived");
    if (sanitiseFileName("  padded  ", ".txt") != "padded.txt")
        return bad("surrounding spaces survived");

    // Nothing usable left is reported as nothing, never as a default: the
    // writers decide what to do about that, and both fall back to the name
    // they proposed rather than to a name the operator half typed.
    if (sanitiseFileName("///", ".txt") != "")
        return bad("a name of nothing but slashes did not reduce to nothing");
    if (sanitiseFileName("", ".txt") != "")
        return bad("an empty name did not stay empty");

    // freeFileName steps past what is there. /proc always exists and holds
    // "self", so this needs no scratch directory of its own.
    if (freeFileName("/proc", "self", "") != "self-2")
        return bad("freeFileName did not step past an existing name");
    if (freeFileName("/proc", "definitely-not-here", "") != "definitely-not-here")
        return bad("freeFileName renamed something that was free");

    return true;
}

// ---------------------------------------------------------------------------
// Entropy, headless.
//
// Cannot prove randomness - nothing can - so it proves the properties that a
// broken pool would visibly lose: that a source was actually available, that
// two draws from the same pool differ, and that the result is a mnemonic the
// signing path accepts.
// ---------------------------------------------------------------------------
bool runEntropyChecks(std::string *err)
{
    emit(std::string("entropy-kernel-ready=") +
         (kernelEntropyReady() ? "yes" : "no") +
         " cpu-rdseed=" + (cpuHasRdseed() ? "yes" : "no") +
         " cpu-rdrand=" + (cpuHasRdrand() ? "yes" : "no"));

    SecureBuffer<32> a, b;
    EntropyPool pool;
    EntropyReport report;

    if (!pool.finalise(a.data(), 32, &report, err))
        return false;
    emit("entropy-sources=" + report.describe());

    if (!pool.finalise(b.data(), 32, &report, err))
        return false;
    if (std::memcmp(a.data(), b.data(), 32) == 0) {
        if (err) *err = "two draws from the entropy pool were identical";
        return false;
    }
    emit("entropy-draws-differ=yes");

    // All-zero output would mean the chain never ran. Cheap, and it is the
    // shape of failure a broken HMAC would produce.
    bool anyNonZero = false;
    for (std::size_t i = 0; i < 32; ++i)
        anyNonZero = anyNonZero || (a.data()[i] != 0);
    if (!anyNonZero) {
        if (err) *err = "the entropy pool produced all zeroes";
        return false;
    }

    for (const std::size_t words : { std::size_t(12), std::size_t(24) }) {
        SecureString generated;
        SecureBuffer<32> entropy;
        const std::size_t need = entropyBytesForWords(words);
        if (need == 0 || !pool.finalise(entropy.data(), need, &report, err))
            return false;
        if (!mnemonicFromEntropy(entropy.data(), need, &generated, err))
            return false;
        if (generated.wordCount() != words) {
            if (err) *err = "a generated mnemonic had the wrong word count";
            return false;
        }
        // Validated by the same checker the signing screen uses, so a mnemonic
        // this device mints is one this device will accept back.
        if (!bip39Validate(generated, err))
            return false;
        emit("entropy-generated-mnemonic-words=" + std::to_string(words) + " valid=yes");
    }
    return true;
}

// ---------------------------------------------------------------------------
// SecureString's grid view, headless.
//
// This is memmove arithmetic over a buffer that holds seeds, and it is the only
// place in the tree where a secret is edited in the middle rather than appended
// to and truncated. An off-by-one here does not crash: it silently shifts a
// word, and what the operator reads back off the grid is then not what will be
// derived from. So it is checked here rather than by eye.
//
// The two mnemonic grids (screen_create's verification, screen_import's entry)
// are Qt and cannot be driven from this binary. What can be driven is every
// operation they call, which is all of this.
// ---------------------------------------------------------------------------
bool runGridChecks(std::string *err)
{
    auto bad = [&](const char *what) {
        if (err) *err = what;
        return false;
    };

    auto typeInto = [](SecureString &s, std::size_t cell, const char *word) {
        for (const char *p = word; *p != '\0'; ++p)
            s.appendToSlot(cell, *p);
    };

    {
        SecureString s;
        if (!s.setSlotCount(12) || s.slotCount() != 12 || s.size() != 11)
            return bad("12 empty cells are not 11 separators");
        if (s.wordCount() != 0 || s.firstEmptySlot() != 0)
            return bad("an empty grid does not report itself empty");

        // A gap in the middle must stay a cell of its own: filling it must not
        // slide the words after it, and emptying one must not remove it.
        typeInto(s, 0, "abandon");
        typeInto(s, 11, "about");
        if (s.slotCount() != 12 || s.firstEmptySlot() != 1)
            return bad("a gap between two filled cells collapsed");
        if (s.slotLength(11) != 5)
            return bad("the last cell moved when an earlier one was empty");

        typeInto(s, 5, "ability");
        if (s.slotLength(11) != 5 || s.slotLength(0) != 7)
            return bad("filling a middle cell disturbed its neighbours");
        s.clearSlot(5);
        if (s.slotCount() != 12 || s.slotLength(11) != 5)
            return bad("clearing a middle cell removed it");
        if (!s.setSlot(5, "ability", 7) || s.slotLength(5) != 7)
            return bad("setSlot did not restore a cleared cell");

        // Structure is not typeable: only setSlotCount() may change the count.
        if (s.appendToSlot(3, ' ') || s.setSlot(3, "a b", 3))
            return bad("a separator was accepted as a character");
        if (s.slotCount() != 12)
            return bad("a rejected edit changed the grid anyway");

        // Shrinking must wipe, not merely truncate.
        if (!s.setSlotCount(6) || s.slotCount() != 6)
            return bad("the grid did not shrink");
        for (std::size_t i = s.size(); i < s.size() + 6 && i < SecureString::kCapacity; ++i) {
            if (s.c_str()[i] != '\0')
                return bad("shrinking left the dropped words behind the terminator");
        }
    }

    // A complete grid must be byte-for-byte the canonical form BIP39 wants -
    // this is what lets the screens hand the buffer straight to bip39Validate()
    // with no rebuild step that could disagree with what was displayed.
    {
        static const char *kWords[12] = {
            "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon", "abandon", "about",
        };
        SecureString s;
        s.setSlotCount(12);
        for (std::size_t i = 0; i < 12; ++i)
            typeInto(s, i, kWords[i]);
        if (s.wordCount() != s.slotCount())
            return bad("a full grid still reports an empty cell");
        if (!bip39Validate(s, err))
            return false;
        if (bip39UnknownSlots(s, -1) != 0)
            return bad("a valid mnemonic was reported as holding unknown words");
        emit("grid-complete-is-canonical=yes");
    }

    // The per-cell wordlist check: empty is not wrong, the cell being typed is
    // not wrong, and everything else is judged.
    {
        SecureString s;
        s.setSlotCount(4);
        typeInto(s, 0, "abandon");
        typeInto(s, 1, "qqqq");     // not a word
        typeInto(s, 3, "aban");     // a prefix, not yet a word
        if (bip39UnknownSlots(s, -1) != ((1u << 1) | (1u << 3)))
            return bad("bip39UnknownSlots did not name exactly the bad cells");
        if (bip39UnknownSlots(s, 3) != (1u << 1))
            return bad("the cell being typed was judged as finished");
        emit("grid-unknown-word-detection=yes");
    }

    return true;
}

} // namespace

int runSelfTest(const SelfTestOptions &opt)
{
    emit("begin");

    std::string initWarning;
    if (!PsbtEngine::initLibrary(&initWarning))
        return fail("libwally-core failed to initialise");
    if (!initWarning.empty())
        emit("note=" + initWarning);
    emit("libwally=" + PsbtEngine::libraryVersion());
    emit("pages-locked=" + std::string(allPagesLocked() ? "yes" : "no"));
    reportNetworkAbsence();

    bool netOk = false;
    const Network net = networkFromString(opt.network, &netOk);
    if (!netOk)
        return fail("unknown network '" + opt.network + "'");
    emit("network=" + std::string(networkName(net)));

    // --- locate the PSBT -------------------------------------------------
    std::string psbtPath = opt.psbtPath;
    if (psbtPath.empty()) {
        const std::vector<PsbtFileEntry> files = listPsbtFiles(opt.dataDir);
        emit("candidates=" + std::to_string(files.size()) + " dir=" + opt.dataDir);
        for (const PsbtFileEntry &f : files) {
            if (!f.isSignerOutput) {
                psbtPath = f.path;
                break;
            }
        }
        if (psbtPath.empty())
            return fail("no unsigned *.psbt file found in " + opt.dataDir);
    }
    emit("psbt=" + psbtPath);

    PsbtEngine engine(net);
    std::string err;
    if (!engine.load(psbtPath, &err))
        return fail("load: " + err);

    const TxSummary &s = engine.summary();
    emit("psbt-version=" + std::to_string(s.psbtVersion) +
         " tx-version=" + std::to_string(s.txVersion) +
         " locktime=" + std::to_string(s.locktime));
    emit("txid=" + s.txid);
    emit("inputs=" + std::to_string(s.inputs.size()) +
         " outputs=" + std::to_string(s.outputs.size()) +
         " with-derivation=" + std::to_string(s.inputsWithDerivation));

    for (std::size_t i = 0; i < s.inputs.size(); ++i) {
        const InputInfo &in = s.inputs[i];
        emit("input[" + std::to_string(i) + "] " + in.outpoint +
             " type=" + in.scriptType +
             " amount=" + (in.amountKnown ? formatSat(in.amountSat) : std::string("UNKNOWN")) +
             " addr=" + in.address +
             " path=" + (in.derivation.empty() ? std::string("-") : in.derivation));
    }
    for (std::size_t i = 0; i < s.outputs.size(); ++i) {
        const OutputInfo &out = s.outputs[i];
        emit("output[" + std::to_string(i) + "] " + out.address +
             " type=" + out.scriptType +
             " amount=" + formatSat(out.amountSat) +
             " owner=" + ownershipName(out.ownership) +
             (out.derivation.empty() ? std::string() : " path=" + out.derivation));
    }

    emit("total-in=" + formatSat(s.totalInSat) + " total-out=" + formatSat(s.totalOutSat));
    if (!s.feeKnown)
        return fail("the fee could not be determined from this PSBT");
    emit("fee=" + formatSat(s.feeSat) + " sat (" + formatBtc(s.feeSat) + " BTC)");
    emit("vsize=" + std::to_string(s.estimatedVsize) +
         " feerate=" + formatFeeRate(s.feeRate) + " sat/vB");

    for (const Finding &f : s.findings) {
        const char *sev = (f.severity == Severity::Danger) ? "DANGER"
                        : (f.severity == Severity::Warning) ? "WARN" : "INFO";
        emit(std::string("finding=") + sev + " " + f.text);
    }

    if (!s.safeToSign)
        return fail("safety gate refused the PSBT: " + s.blockReason);
    emit("safe-to-sign=yes");

    // --- key -------------------------------------------------------------
    if (opt.mnemonicFile.empty())
        return fail("no --mnemonic-file given, so there is nothing to sign with");

    SecureString mnemonic, passphrase;
    if (!readMnemonicFile(opt.mnemonicFile, &mnemonic, &err))
        return fail("mnemonic file: " + err);
    emit("mnemonic-words=" + std::to_string(mnemonic.wordCount()));

    // --- wallet creation --------------------------------------------------
    //
    // Before anything sets the signing key: the master key slot is process-wide
    // and buildWalletExport() takes it over and then clears it.
    if (!runGridChecks(&err))
        return fail("mnemonic grid: " + err);
    if (!runFileNameChecks(&err))
        return fail("file names: " + err);
    if (!runEntropyChecks(&err))
        return fail("entropy: " + err);
    if (!runWalletChecks(net, mnemonic, 0, "", &err))
        return fail("wallet export: " + err);
    // And once more for an account the operator can pick on the import screen.
    // Account 0 is not a proof that the index is used correctly - it is the one
    // value for which a dropped or mis-hardened index still gives the right
    // answer.
    if (!runWalletChecks(net, mnemonic, 1, "-acct1", &err))
        return fail("wallet export (account 1): " + err);

    // --- the change-labelling gate ---------------------------------------
    //
    // A PSBT that attaches this wallet's fingerprint and a plausible derivation
    // path to an output it does not control is the one input that could talk an
    // operator into authorising their own loss: the screen would call the
    // attacker's address "change coming back to you". This runs that file
    // through the same engine and requires a refusal.
    //
    // In its own scope, and before the real key is set: the master key lives in
    // a single process-wide slot, so this engine must be gone before the one
    // that signs takes it over.
    if (!opt.blockedPsbtPath.empty()) {
        PsbtEngine attack(net);
        if (!attack.load(opt.blockedPsbtPath, &err))
            return fail("change-attack fixture: " + err);
        if (!attack.setKeyFromMnemonic(mnemonic, passphrase, &err))
            return fail("change-attack fixture key: " + err);

        bool sawMismatch = false;
        for (const OutputInfo &out : attack.summary().outputs)
            if (out.ownership == OutputOwnership::Mismatch)
                sawMismatch = true;
        if (!sawMismatch)
            return fail("a forged change output was NOT identified as a mismatch");
        if (attack.summary().safeToSign)
            return fail("a forged change output did not block signing");

        std::size_t added = 0;
        if (attack.sign(&added, &err))
            return fail("the engine signed a PSBT with a forged change output");
        emit("change-attack-blocked=yes reason=" + attack.summary().blockReason);
    }

    if (!engine.setKeyFromMnemonic(mnemonic, passphrase, &err))
        return fail("key: " + err);
    mnemonic.clear();

    emit("fingerprint=" + engine.masterFingerprint());
    emit("signable=" + std::to_string(engine.summary().signableInputs) + "/" +
         std::to_string(engine.summary().inputs.size()));

    if (engine.summary().signableInputs == 0)
        return fail("this key can sign none of the inputs");

    // The inspection above ran without a key, so every output could only be
    // reported as claimed. Now that there is a key, say what was proved.
    for (std::size_t i = 0; i < engine.summary().outputs.size(); ++i) {
        const OutputInfo &out = engine.summary().outputs[i];
        emit("output-verified[" + std::to_string(i) + "] owner=" +
             ownershipName(out.ownership) +
             (out.derivation.empty() ? std::string() : " path=" + out.derivation));
        if (out.ownership == OutputOwnership::Mismatch)
            return fail("output " + std::to_string(i + 1) +
                        " claims to be our change but is not");
    }
    emit("verified-change=" + formatSat(engine.summary().verifiedChangeSat) +
         " leaving-wallet=" + formatSat(engine.summary().leavingSat));

    // The findings printed above were the ones knowable without a key. Change
    // labelling produces its own, so the list is restated rather than left as
    // the pre-key version.
    for (const Finding &f : engine.summary().findings) {
        const char *sev = (f.severity == Severity::Danger) ? "DANGER"
                        : (f.severity == Severity::Warning) ? "WARN" : "INFO";
        emit(std::string("finding-verified=") + sev + " " + f.text);
    }

    // safeToSign is recomputed with the key in hand; the pre-key check above
    // could not see a forged change output.
    if (!engine.summary().safeToSign)
        return fail("safety gate refused the PSBT once the key was known: " +
                    engine.summary().blockReason);

    const std::string txidBefore = engine.summary().txid;

    // --- sign ------------------------------------------------------------
    std::size_t added = 0;
    if (!engine.sign(&added, &err))
        return fail("sign: " + err);
    emit("signatures-added=" + std::to_string(added));
    if (added == 0)
        return fail("signing reported success but added no signatures");

    // Signing must not change what is being spent. For SIGHASH_ALL the
    // unsigned txid is committed to by every signature, so any drift here means
    // the transaction was mutated - which would be a serious bug.
    if (engine.summary().txid != txidBefore)
        return fail("the txid changed while signing (before=" + txidBefore +
                    " after=" + engine.summary().txid + ")");
    emit("txid-stable=yes");

    // --- write and read back ---------------------------------------------
    // The empty name is the headless path through the save-as step the GUI
    // shows: writeResult() falls back to the name it would have proposed.
    std::string outPsbt, outTx;
    if (!engine.writeResult(opt.dataDir, std::string(), opt.writeFinalTx,
                            &outPsbt, &outTx, &err))
        return fail("write: " + err);
    emit("wrote=" + outPsbt);
    if (!outTx.empty())
        emit("wrote-final-tx=" + outTx);

    struct stat st {};
    if (::stat(outPsbt.c_str(), &st) != 0 || st.st_size <= 0)
        return fail("the output file is missing or empty after writing");
    emit("output-bytes=" + std::to_string(static_cast<long long>(st.st_size)));

    // Re-parse what we just wrote with a fresh engine: proves the artefact on
    // the medium is a valid PSBT carrying the signatures, not just that our
    // in-memory object looked right.
    {
        PsbtEngine verify(net);
        if (!verify.load(outPsbt, &err))
            return fail("the file we wrote does not parse: " + err);

        std::size_t sigs = 0;
        for (const InputInfo &in : verify.summary().inputs)
            sigs += in.existingSignatures;
        emit("readback-signatures=" + std::to_string(sigs));
        if (sigs < added)
            return fail("the file we wrote contains fewer signatures than we added");
        if (verify.summary().txid != txidBefore)
            return fail("the file we wrote describes a different transaction");
        emit("readback-txid-matches=yes");
    }

    if (!opt.keepOutput) {
        ::unlink(outPsbt.c_str());
        if (!outTx.empty())
            ::unlink(outTx.c_str());
        emit("output-removed=yes");
    }

    emit("PASS");
    return 0;
}

} // namespace signeros
