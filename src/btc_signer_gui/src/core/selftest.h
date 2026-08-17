// SPDX-License-Identifier: MIT
//
// selftest.h - headless end-to-end exercise of the signing path.
//
// Same binary, same PsbtEngine, same unprivileged account as the GUI - only the
// user interface is missing. That is what makes it useful as a build gate: a
// passing self-test is evidence about the artefact you are about to flash, not
// about a separate test program.
//
// Consumed by scripts/test_in_qemu.sh (inside the VM, driven by
// signeros.selftest=1) and by scripts/host_selftest.sh (on the build machine,
// against a host-built libwally).

#pragma once

#include <string>

namespace signeros {

struct SelfTestOptions {
    std::string dataDir = "/mnt/data";
    std::string psbtPath;        // empty: pick the first candidate in dataDir
    std::string mnemonicFile;    // required
    // Optional negative fixture: a PSBT whose change output claims this
    // wallet's fingerprint over an address it does not control. The self-test
    // requires the engine to refuse it. Empty: skip that check.
    std::string blockedPsbtPath;
    std::string network = "mainnet";
    bool writeFinalTx = false;
    bool keepOutput = true;      // false: unlink what it wrote (host runs)
};

// Prints machine-readable "SELFTEST: <key>=<value>" lines to stdout, then
// "SELFTEST: PASS" or "SELFTEST: FAIL <reason>". Returns 0 on pass.
int runSelfTest(const SelfTestOptions &opt);

} // namespace signeros
