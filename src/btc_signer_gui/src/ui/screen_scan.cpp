// SPDX-License-Identifier: MIT

#include "ui/screen_scan.h"

#include <QAbstractItemView>
#include <QColor>
#include <QDateTime>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>

#include "ui/app_window.h"
#include "ui/theme.h"

namespace signeros {
namespace {

QString humanSize(std::uint64_t bytes)
{
    if (bytes < 1024)
        return QStringLiteral("%1 B").arg(bytes);
    if (bytes < 1024 * 1024)
        return QStringLiteral("%1.%2 KiB").arg(bytes / 1024).arg((bytes % 1024) * 10 / 1024);
    return QStringLiteral("%1 MiB").arg(bytes / (1024 * 1024));
}

QString humanTime(std::int64_t epoch)
{
    if (epoch <= 0)
        return QStringLiteral("unknown time");
    const QDateTime dt = QDateTime::fromSecsSinceEpoch(static_cast<qint64>(epoch));
    if (dt.date().year() < 2020)
        return QStringLiteral("no timestamp");
    return dt.toString(QStringLiteral("yyyy-MM-dd HH:mm"));
}

} // namespace

ScanScreen::ScanScreen(AppWindow *app, QWidget *parent) : QWidget(parent), app_(app)
{
    auto *outer = new QVBoxLayout(this);
    outer->setContentsMargins(theme::px(24), theme::px(16), theme::px(24), theme::px(20));
    outer->setSpacing(theme::px(10));

    // The file list and its explanation live in a column that stops growing
    // once it is wide enough to read: on a desktop monitor the alternative is a
    // filename at the far left and its timestamp a foot away at the right.
    auto *column = new QWidget(this);
    auto *v = new QVBoxLayout(column);
    v->setContentsMargins(0, 0, 0, 0);
    v->setSpacing(theme::px(10));

    v->addWidget(theme::heading(QStringLiteral("Choose a transaction to review"), column));
    v->addWidget(theme::dim(
        QStringLiteral("Files ending in .psbt on the %1 partition, mounted read-write "
                       "but never executable.")
            .arg(app_->config().dataLabel), column));

    errorLabel_ = new QLabel(column);
    errorLabel_->setFont(theme::uiFont(16, true));
    errorLabel_->setWordWrap(true);
    errorLabel_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::danger()));
    errorLabel_->hide();
    v->addWidget(errorLabel_);

    list_ = new QListWidget(column);
    list_->setFont(theme::monoFont(16));
    list_->setSelectionMode(QAbstractItemView::SingleSelection);
    list_->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    v->addWidget(list_, 1);

    emptyHint_ = new QLabel(column);
    emptyHint_->setFont(theme::uiFont(16));
    emptyHint_->setWordWrap(true);
    emptyHint_->setAlignment(Qt::AlignCenter);
    emptyHint_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::textDim()));
    v->addWidget(emptyHint_, 1);

    outer->addWidget(theme::centeredColumn(column, theme::px(1040), this), 1);

    auto *buttons = new QHBoxLayout;
    buttons->setSpacing(theme::px(12));

    // Not named `refresh`: a local of that name would shadow the refresh()
    // member, and the lambda further down calls refresh() without capturing it.
    QPushButton *refreshBtn = theme::secondaryButton(QStringLiteral("Refresh"), this);
    connect(refreshBtn, &QPushButton::clicked, this, &ScanScreen::refresh);
    buttons->addWidget(refreshBtn);

    QPushButton *back = theme::secondaryButton(QStringLiteral("Back"), this);
    connect(back, &QPushButton::clicked, app_, &AppWindow::showHome);
    buttons->addWidget(back);

    buttons->addStretch(1);

    inspectBtn_ = theme::primaryButton(QStringLiteral("Review transaction"), this);
    connect(inspectBtn_, &QPushButton::clicked, this, &ScanScreen::openSelected);
    buttons->addWidget(inspectBtn_);

    outer->addLayout(buttons);

    connect(list_, &QListWidget::itemSelectionChanged, this, &ScanScreen::updateButtons);
    connect(list_, &QListWidget::itemDoubleClicked, this, &ScanScreen::openSelected);
    // itemActivated covers Enter/Return on the focused list, so the screen is
    // fully usable from a physical keyboard with no pointer at all.
    connect(list_, &QListWidget::itemActivated, this, &ScanScreen::openSelected);

    // The stick is often inserted after boot. Polling is cheap and it removes an
    // entire class of "why is my file not showing up" confusion.
    autoRefresh_ = new QTimer(this);
    autoRefresh_->setInterval(2500);
    connect(autoRefresh_, &QTimer::timeout, this, &ScanScreen::refresh);

    connect(app_, &AppWindow::dataStatusChanged, this, [this](bool) { refresh(); });
}

void ScanScreen::onEnter()
{
    refresh();
    autoRefresh_->start();
}

void ScanScreen::onLeave()
{
    autoRefresh_->stop();
}

void ScanScreen::refresh()
{
    // Preserve the selection across refreshes by name, not by row: rows move
    // when a new file appears, and selecting a different transaction than the
    // one the operator picked would be unforgivable.
    QString selectedName;
    if (QListWidgetItem *cur = list_->currentItem())
        selectedName = cur->data(Qt::UserRole + 1).toString();

    list_->clear();

    if (!app_->dataMounted()) {
        errorLabel_->setText(
            QStringLiteral("The %1 partition is not mounted.\n\n"
                           "Insert the USB stick now - it is picked up automatically, "
                           "there is no need to restart. Partition 2 must be FAT32 or "
                           "exFAT with the filesystem label %1.")
                .arg(app_->config().dataLabel));
        errorLabel_->show();
        emptyHint_->hide();
        list_->hide();
        updateButtons();
        return;
    }
    errorLabel_->hide();

    const std::vector<PsbtFileEntry> files =
        listPsbtFiles(app_->config().dataDir.toStdString());

    if (files.empty()) {
        list_->hide();
        emptyHint_->setText(
            QStringLiteral("No .psbt files on the %1 partition.\n\n"
                           "Copy an unsigned PSBT into the root of that partition on "
                           "your online machine, then plug the stick in here.")
                .arg(app_->config().dataLabel));
        emptyHint_->show();
        updateButtons();
        return;
    }

    emptyHint_->hide();
    list_->show();

    for (const PsbtFileEntry &f : files) {
        const QString name = QString::fromStdString(f.name);
        QString label = QStringLiteral("%1\n    %2   %3")
                            .arg(name, humanSize(f.sizeBytes), humanTime(f.mtime));
        if (f.isSignerOutput)
            label += QStringLiteral("   [signed here earlier]");

        auto *item = new QListWidgetItem(label, list_);
        item->setData(Qt::UserRole, QString::fromStdString(f.path));
        item->setData(Qt::UserRole + 1, name);
        if (f.isSignerOutput)
            item->setForeground(QColor(QString::fromLatin1(theme::textDim())));
        if (name == selectedName)
            list_->setCurrentItem(item);
    }

    if (list_->currentItem() == nullptr && list_->count() > 0)
        list_->setCurrentRow(0);

    updateButtons();
}

void ScanScreen::updateButtons()
{
    inspectBtn_->setEnabled(list_->isVisible() && list_->currentItem() != nullptr);
}

void ScanScreen::openSelected()
{
    QListWidgetItem *item = list_->currentItem();
    if (item == nullptr)
        return;

    const QString path = item->data(Qt::UserRole).toString();

    std::string err;
    if (!app_->engine().load(path.toStdString(), &err)) {
        errorLabel_->setText(QStringLiteral("Cannot read %1\n\n%2")
                                 .arg(item->data(Qt::UserRole + 1).toString(),
                                      QString::fromStdString(err)));
        errorLabel_->show();
        return;
    }

    errorLabel_->hide();
    app_->showInspect();
}

} // namespace signeros
