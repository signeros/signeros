// SPDX-License-Identifier: MIT
//
// secret_buffers.h - every secret this process can hold, in one place.
//
// The signing screen used to own its two SecureStrings as file-scope statics of
// screen_sign.cpp, with a comment explaining that there is exactly one mnemonic
// buffer and one passphrase buffer in the address space. Wallet creation needs
// a mnemonic and a passphrase too, and giving it its own pair would have
// quietly made that comment false - two more page ranges that can contain a
// seed, in a different translation unit, wiped by a different code path.
//
// So the buffers moved here and both screens share them. The invariant is
// unchanged and now enforced by there being nowhere else to put a secret:
//
//   * one mnemonic buffer - the words being typed to sign, or the words just
//     generated for a new wallet. Never both at once: the two flows are
//     reachable only through the home screen, which wipes on the way past.
//   * one passphrase buffer.
//   * one verification buffer, which exists only because verifying a freshly
//     generated mnemonic means holding the generated words and the re-typed
//     words at the same time in order to compare them.
//   * one passphrase confirmation buffer, which exists for exactly the same
//     reason one step later: every screen that takes a passphrase asks for it
//     twice, and comparing the two means holding both.
//
// All four are fixed-capacity, page-locked and self-wiping (see
// core/secure_memory.h), and all four are cleared by wipeAllSecrets().

#pragma once

#include <QString>

namespace signeros {

class SecureString;

// The mnemonic in hand: typed by the operator on the signing screen, or minted
// by the wallet creation screen.
SecureString &mnemonicBuffer();

// The BIP39 passphrase, on both screens.
SecureString &passphraseBuffer();

// Where the operator re-types a freshly generated mnemonic so the device can
// prove the backup they just wrote down is correct. Never used by the signing
// path.
SecureString &verificationBuffer();

// Where the operator types the passphrase a second time.
//
// A passphrase is the one secret on this machine that nothing can check: any
// bytes are legal, so a slip produces a different, valid, empty wallet rather
// than an error. Typing it twice is the only check that exists, and showing it
// in clear (which every screen now does) is the other half - the two catch
// different mistakes, a slip and a keyboard layout respectively.
SecureString &passphraseConfirmBuffer();

// Whether the two passphrase buffers hold the same text. Always the question
// asked before deriving anything: an unconfirmed passphrase is not usable.
bool passphraseConfirmed();

// Clears all four. Called whenever a screen that can hold key material is
// left, and on the way to poweroff.
void wipeAllSecrets();

// The readable form of a secret the operator has asked to see, in lines of at
// most `lineLength` characters.
//
// A passphrase is one token with no spaces in it, and a QLabel asked to lay out
// an unbreakable 160-character token reports a *minimum* width of 160
// characters - it has nowhere to wrap. That minimum travels up through the
// layout to the QStackedWidget holding the screens, which takes the widest
// minimum of every page it holds, so one long passphrase pushed the window past
// the edge of the panel and carried the buttons in the bottom right of the
// pages after it out of sight. Breaking the line here is what gives the label
// somewhere to wrap; AppWindow's size cap is the second line of defence.
//
// It also happens to be the only conversion of a secret to a QString in the
// process that produces exactly one string: the buffer is reserved up front and
// the characters are appended into it, rather than a fromUtf8() whose result is
// then handed to an .arg() that copies it again.
QString revealedSecret(const SecureString &s, int lineLength = 32);

} // namespace signeros
