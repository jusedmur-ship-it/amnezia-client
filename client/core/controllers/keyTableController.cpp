#include "keyTableController.h"

#include <QCryptographicHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QSet>

#include "core/controllers/connectionController.h"
#include "core/controllers/selfhosted/importController.h"
#include "core/repositories/secureServersRepository.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/serverConfigUtils.h"
#include "ui/controllers/connectionUiController.h"

using namespace amnezia;

namespace
{
    constexpr QLatin1String keyTableUrlKey("key_table_url");
    constexpr QLatin1String keyTableSeatKey("key_table_seat");
    constexpr QLatin1String keyTableAppliedKey("key_table_applied");

    constexpr int firstCheckDelayMsec = 3000;
    constexpr int periodicCheckMsec = 60 * 60 * 1000;
    constexpr int connectingTooLongMsec = 40 * 1000;
    constexpr int disconnectGuardMsec = 15 * 1000;
    constexpr int requestTimeoutMsec = 20 * 1000;
    constexpr int reconnectDelayMsec = 1000;
    constexpr qint64 fallbackCheckIntervalSec = 5 * 60;

    QString unquoted(QString field)
    {
        field = field.trimmed();
        field.remove(QChar(0xFEFF));
        if (field.size() >= 2 && field.startsWith('"') && field.endsWith('"')) {
            field = field.mid(1, field.size() - 2).trimmed();
        }
        return field;
    }

    int seatFromValue(const QJsonValue &value)
    {
        if (value.isDouble()) {
            return value.toInt();
        }
        bool ok = false;
        const int seat = value.toString().trimmed().toInt(&ok);
        return ok ? seat : 0;
    }

    QString keyHash(const QString &key)
    {
        return QString::fromLatin1(QCryptographicHash::hash(key.toUtf8(), QCryptographicHash::Sha256).toHex());
    }
}

KeyTableController::KeyTableController(SecureServersRepository *serversRepository, ImportController *importController,
                                       ConnectionController *connectionController,
                                       ConnectionUiController *connectionUiController, QObject *parent)
    : QObject(parent),
      m_serversRepository(serversRepository),
      m_importController(importController),
      m_connectionUiController(connectionUiController)
{
    m_periodicTimer.setInterval(periodicCheckMsec);
    connect(&m_periodicTimer, &QTimer::timeout, this, [this]() {
        if (m_phase == Phase::Idle) {
            checkTables();
        }
    });

    m_connectingTimer.setInterval(connectingTooLongMsec);
    connect(&m_connectingTimer, &QTimer::timeout, this, &KeyTableController::onConnectingTooLong);

    m_disconnectGuardTimer.setSingleShot(true);
    m_disconnectGuardTimer.setInterval(disconnectGuardMsec);
    connect(&m_disconnectGuardTimer, &QTimer::timeout, this, &KeyTableController::checkAfterDisconnect);

    connect(connectionController, &ConnectionController::connectionStateChanged, this,
            &KeyTableController::onConnectionStateChanged);
}

void KeyTableController::start()
{
    QTimer::singleShot(firstCheckDelayMsec, this, [this]() {
        if (m_phase == Phase::Idle) {
            checkTables();
        }
    });
    m_periodicTimer.start();
}

QStringList KeyTableController::tableUrls() const
{
    QStringList urls;
    for (const QString &serverId : m_serversRepository->orderedServerIds()) {
        const auto serverJson = m_serversRepository->serverJsonById(serverId);
        if (!serverJson.has_value()) {
            continue;
        }
        const QString url = serverJson->value(keyTableUrlKey).toString().trimmed();
        if (!url.isEmpty() && !urls.contains(url)) {
            urls.append(url);
        }
    }
    return urls;
}

void KeyTableController::checkTables()
{
    if (m_phase == Phase::Checking) {
        return;
    }

    const QStringList urls = tableUrls();
    m_phase = Phase::Checking;
    m_defaultServerChanged = false;
    m_pendingReplies = urls.size();

    if (urls.isEmpty()) {
        finishCheck();
        return;
    }

    qInfo() << "KeyTable: checking" << urls.size() << "table(s)";
    for (const QString &url : urls) {
        QNetworkRequest request { QUrl(url) };
        request.setTransferTimeout(requestTimeoutMsec);
        request.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
        request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);
        QNetworkReply *reply = m_networkManager.get(request);
        connect(reply, &QNetworkReply::finished, this, [this, reply, url]() { onReplyFinished(reply, url); });
    }
}

void KeyTableController::onReplyFinished(QNetworkReply *reply, const QString &url)
{
    reply->deleteLater();

    if (reply->error() == QNetworkReply::NoError) {
        if (applyTable(url, reply->readAll())) {
            m_defaultServerChanged = true;
        }
    } else {
        qWarning() << "KeyTable: table download failed:" << reply->error();
    }

    if (--m_pendingReplies <= 0) {
        finishCheck();
    }
}

void KeyTableController::finishCheck()
{
    const bool reconnect = m_reconnectAfterCheck;
    m_reconnectAfterCheck = false;
    m_phase = Phase::Idle;

    emit tablesChecked(m_defaultServerChanged);

    if (reconnect) {
        connectDefaultServer();
        return;
    }

    if (m_defaultServerChanged && !isDisconnected()) {
        qInfo() << "KeyTable: reconnecting with the new key";
        m_phase = Phase::WaitingDisconnectToReconnect;
        m_connectionUiController->closeConnection();
    }
}

QHash<int, QString> KeyTableController::parseTable(const QByteArray &csv)
{
    static const QRegularExpression separator(QStringLiteral("[,;\\t]"));
    static const QRegularExpression vpnKey(QStringLiteral("vpn://[A-Za-z0-9_\\-=]+"));

    QHash<int, QString> table;
    const QStringList lines = QString::fromUtf8(csv).split('\n');
    for (const QString &line : lines) {
        const int separatorIndex = line.indexOf(separator);
        if (separatorIndex <= 0) {
            continue;
        }

        bool ok = false;
        const int seat = unquoted(line.left(separatorIndex)).toInt(&ok);
        if (!ok || seat <= 0) {
            continue;
        }

        const QRegularExpressionMatch match = vpnKey.match(line, separatorIndex);
        if (match.hasMatch()) {
            table.insert(seat, match.captured(0));
        }
    }
    return table;
}

int KeyTableController::seatOfServer(const QJsonObject &serverJson)
{
    if (serverJson.contains(keyTableSeatKey)) {
        return seatFromValue(serverJson.value(keyTableSeatKey));
    }

    const QJsonArray containers = serverJson.value(configKey::containers).toArray();
    for (const QJsonValue &containerValue : containers) {
        const QJsonObject container = containerValue.toObject();
        for (auto it = container.constBegin(); it != container.constEnd(); ++it) {
            const QString lastConfig = it.value().toObject().value(configKey::lastConfig).toString();
            if (lastConfig.isEmpty()) {
                continue;
            }
            const QString clientIp = QJsonDocument::fromJson(lastConfig.toUtf8()).object().value(configKey::clientIp).toString();
            bool ok = false;
            const int seat = clientIp.section('/', 0, 0).section('.', -1).toInt(&ok);
            if (ok && seat > 0) {
                return seat;
            }
        }
    }
    return 0;
}

bool KeyTableController::applyTable(const QString &url, const QByteArray &csv)
{
    const QHash<int, QString> table = parseTable(csv);
    if (table.isEmpty()) {
        qWarning() << "KeyTable: table has no keys";
        return false;
    }

    bool defaultServerChanged = false;
    const QString defaultServerId = m_serversRepository->defaultServerId();

    for (const QString &serverId : m_serversRepository->orderedServerIds()) {
        const auto currentJson = m_serversRepository->serverJsonById(serverId);
        if (!currentJson.has_value() || currentJson->value(keyTableUrlKey).toString().trimmed() != url) {
            continue;
        }

        const int seat = seatOfServer(*currentJson);
        const QString key = table.value(seat);
        if (seat <= 0 || key.isEmpty()) {
            qWarning() << "KeyTable: no key for seat" << seat;
            continue;
        }

        const QString hash = keyHash(key);
        if (currentJson->value(keyTableAppliedKey).toString() == hash) {
            continue;
        }

        const auto importResult = m_importController->extractConfigFromData(key);
        if (importResult.errorCode != ErrorCode::NoError || importResult.config.isEmpty()) {
            qWarning() << "KeyTable: key for seat" << seat << "is invalid";
            continue;
        }

        QJsonObject updatedJson = importResult.config;
        const auto kind = serverConfigUtils::configTypeFromJson(updatedJson);
        if (kind != m_serversRepository->serverKind(serverId)) {
            qWarning() << "KeyTable: key for seat" << seat << "has another config type";
            continue;
        }
        if (!updatedJson.contains(keyTableUrlKey)) {
            updatedJson.insert(keyTableUrlKey, url);
        }
        if (currentJson->contains(keyTableSeatKey) && !updatedJson.contains(keyTableSeatKey)) {
            updatedJson.insert(keyTableSeatKey, currentJson->value(keyTableSeatKey));
        }
        if (seatOfServer(updatedJson) != seat) {
            qWarning() << "KeyTable: key in row" << seat << "belongs to another seat";
            continue;
        }
        updatedJson.insert(keyTableAppliedKey, hash);

        const bool contentChanged = updatedJson.value(configKey::containers) != currentJson->value(configKey::containers)
                || updatedJson.value(configKey::hostName) != currentJson->value(configKey::hostName);

        m_serversRepository->editServer(serverId, updatedJson, kind);

        if (contentChanged) {
            qInfo() << "KeyTable: key for seat" << seat << "replaced";
            if (serverId == defaultServerId) {
                defaultServerChanged = true;
            }
        }
    }
    return defaultServerChanged;
}

void KeyTableController::onConnectionStateChanged(Vpn::ConnectionState state)
{
    m_state = state;

    if (state == Vpn::ConnectionState::Connecting || state == Vpn::ConnectionState::Reconnecting) {
        if (!m_connectingTimer.isActive()) {
            m_connectingTimer.start();
        }
    } else {
        m_connectingTimer.stop();
    }

    if (!isDisconnected()) {
        return;
    }

    if (m_phase == Phase::WaitingDisconnectToCheck) {
        checkAfterDisconnect();
    } else if (m_phase == Phase::WaitingDisconnectToReconnect) {
        m_phase = Phase::Idle;
        connectDefaultServer();
    }
}

void KeyTableController::onConnectingTooLong()
{
    if (m_phase != Phase::Idle || tableUrls().isEmpty()) {
        return;
    }

    const QDateTime now = QDateTime::currentDateTimeUtc();
    if (m_lastFallbackCheck.isValid() && m_lastFallbackCheck.secsTo(now) < fallbackCheckIntervalSec) {
        return;
    }
    m_lastFallbackCheck = now;

    qInfo() << "KeyTable: no handshake, checking the table";
    m_phase = Phase::WaitingDisconnectToCheck;
    m_disconnectGuardTimer.start();
    m_connectionUiController->closeConnection();
}

void KeyTableController::checkAfterDisconnect()
{
    if (m_phase != Phase::WaitingDisconnectToCheck) {
        return;
    }
    m_disconnectGuardTimer.stop();
    m_reconnectAfterCheck = true;
    checkTables();
}

void KeyTableController::connectDefaultServer()
{
    QTimer::singleShot(reconnectDelayMsec, this, [this]() {
        if (isDisconnected()) {
            m_connectionUiController->toggleConnection();
        }
    });
}

bool KeyTableController::isDisconnected() const
{
    return m_state == Vpn::ConnectionState::Disconnected || m_state == Vpn::ConnectionState::Error
            || m_state == Vpn::ConnectionState::Unknown;
}
