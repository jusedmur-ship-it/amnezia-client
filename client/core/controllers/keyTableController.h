#ifndef KEYTABLECONTROLLER_H
#define KEYTABLECONTROLLER_H

#include <QDateTime>
#include <QHash>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QObject>
#include <QStringList>
#include <QTimer>

#include "core/protocols/vpnProtocol.h"

class SecureServersRepository;
class ImportController;
class ConnectionController;
class ConnectionUiController;
class QNetworkReply;

class KeyTableController : public QObject
{
    Q_OBJECT

public:
    KeyTableController(SecureServersRepository *serversRepository, ImportController *importController,
                       ConnectionController *connectionController, ConnectionUiController *connectionUiController,
                       QObject *parent = nullptr);

    void start();
    void checkTables();
    bool applyTable(const QString &url, const QByteArray &csv);

    static QHash<int, QString> parseTable(const QByteArray &csv);
    static int seatOfServer(const QJsonObject &serverJson);

signals:
    void tablesChecked(bool defaultServerChanged);

private:
    enum class Phase {
        Idle,
        WaitingDisconnectToCheck,
        Checking,
        WaitingDisconnectToReconnect
    };

    void onConnectionStateChanged(Vpn::ConnectionState state);
    void onConnectingTooLong();
    void checkAfterDisconnect();
    void onReplyFinished(QNetworkReply *reply, const QString &url);
    void finishCheck();
    void connectDefaultServer();
    bool isDisconnected() const;
    QStringList tableUrls() const;

    SecureServersRepository *m_serversRepository;
    ImportController *m_importController;
    ConnectionUiController *m_connectionUiController;
    QNetworkAccessManager m_networkManager;

    Vpn::ConnectionState m_state = Vpn::ConnectionState::Disconnected;
    Phase m_phase = Phase::Idle;
    bool m_reconnectAfterCheck = false;
    bool m_defaultServerChanged = false;
    int m_pendingReplies = 0;
    QDateTime m_lastFallbackCheck;

    QTimer m_periodicTimer;
    QTimer m_connectingTimer;
    QTimer m_disconnectGuardTimer;
};

#endif
