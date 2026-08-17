// SPDX-License-Identifier: MIT
//
// Screen 2 - read the transaction.
//
// This screen is the entire reason an air-gapped signer exists. The online
// machine is assumed compromised, so everything the operator is about to
// authorise has to be re-derived here, from the PSBT itself, and shown in a form
// a human can actually check: which coins are being spent, where they are going,
// what the miner gets, and what is unusual about any of it.
//
// Nothing is elided or rounded away. Addresses wrap rather than truncate,
// amounts appear in both BTC and satoshis, and the fee is refused rather than
// estimated when the PSBT does not carry enough information to compute it.

#pragma once

#include <QWidget>

class QLabel;
class QPushButton;
class QScrollArea;
class QVBoxLayout;

namespace signeros {

class AppWindow;

class InspectScreen : public QWidget {
    Q_OBJECT

public:
    explicit InspectScreen(AppWindow *app, QWidget *parent = nullptr);

    // Rebuilds the whole view from the engine's current summary.
    void onEnter();

private:
    void clearContent();
    void addSummary();
    void addFindings();
    void addInputs();
    void addOutputs();
    void scrollBy(int pixels);

    AppWindow *app_ = nullptr;
    QScrollArea *scroll_ = nullptr;
    QWidget *content_ = nullptr;
    QVBoxLayout *contentLayout_ = nullptr;
    QLabel *blockLabel_ = nullptr;
    QPushButton *signBtn_ = nullptr;
};

} // namespace signeros
