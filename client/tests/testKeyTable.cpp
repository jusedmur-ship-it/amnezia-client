#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSignalSpy>
#include <QTest>
#include <QUuid>

#include "core/controllers/keyTableController.h"
#include "secureQSettings.h"
#include "utils/testCoreController.h"
#include "vpnConnection.h"

using namespace amnezia;

namespace
{
    const QString tableUrl = QStringLiteral("https://example.invalid/key-table.csv");

    QJsonObject awgServerJson(const QString &hostName, const QString &clientIp, const QString &url)
    {
        QJsonObject lastConfig {
            { "client_ip", clientIp },
            { "client_priv_key", "test-private-key-" + clientIp },
            { "client_pub_key", "test-public-key-" + clientIp },
            { "clientId", "test-public-key-" + clientIp },
            { "server_pub_key", "test-server-key" },
            { "psk_key", "test-psk" },
            { "hostName", hostName },
            { "port", 49971 },
            { "mtu", "1376" },
            { "Jc", "2" }, { "Jmin", "10" }, { "Jmax", "50" }, { "S1", "56" }, { "S2", "119" },
            { "H1", "1" }, { "H2", "2" }, { "H3", "3" }, { "H4", "4" },
            { "config", QStringLiteral("[Interface]\nAddress = %1/32\nPrivateKey = test\n\n[Peer]\nPublicKey = test\n"
                                       "AllowedIPs = 0.0.0.0/0\nEndpoint = %2:49971\n").arg(clientIp, hostName) },
        };

        QJsonObject awg {
            { "last_config", QString::fromUtf8(QJsonDocument(lastConfig).toJson(QJsonDocument::Compact)) },
            { "port", "49971" },
            { "transport_proto", "udp" },
            { "Jc", "2" }, { "Jmin", "10" }, { "Jmax", "50" }, { "S1", "56" }, { "S2", "119" },
            { "H1", "1" }, { "H2", "2" }, { "H3", "3" }, { "H4", "4" },
        };

        QJsonObject server {
            { "containers", QJsonArray { QJsonObject { { "container", "amnezia-awg" }, { "awg", awg } } } },
            { "defaultContainer", "amnezia-awg" },
            { "description", "Test seat " + clientIp },
            { "dns1", "1.1.1.1" },
            { "dns2", "1.0.0.1" },
            { "hostName", hostName },
        };
        if (!url.isEmpty()) {
            server.insert("key_table_url", url);
        }
        return server;
    }

    QString vpnKey(const QJsonObject &server)
    {
        const QByteArray compressed = qCompress(QJsonDocument(server).toJson(QJsonDocument::Compact), 9);
        return "vpn://" + QString::fromLatin1(compressed.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
    }
}

class TestKeyTable : public QObject
{
    Q_OBJECT

private:
    TestCoreController *m_coreController;
    SecureQSettings *m_settings;

    void importKey(const QString &key)
    {
        const auto result = m_coreController->m_importCoreController->extractConfigFromData(key);
        QVERIFY(result.errorCode == ErrorCode::NoError);
        m_coreController->m_importCoreController->importConfig(result.config);
    }

    QString hostOfServer(int index) const
    {
        const QString serverId = m_coreController->m_serversRepository->serverIdAt(index);
        return m_coreController->m_serversRepository->serverJsonById(serverId)->value("hostName").toString();
    }

private slots:
    void initTestCase()
    {
        m_settings = new SecureQSettings("AmneziaVPN-Test-" + QUuid::createUuid().toString(), "amnezia-client", nullptr, false);
        auto vpnConnection = QSharedPointer<VpnConnection>::create(nullptr, nullptr);
        m_coreController = new TestCoreController(vpnConnection, m_settings, nullptr, this);
    }

    void cleanupTestCase()
    {
        m_settings->clearSettings();
        delete m_coreController;
        delete m_settings;
    }

    void init()
    {
        m_settings->clearSettings();
        m_coreController->m_serversRepository->invalidateCache();
    }

    void testParseTable()
    {
        const QByteArray csv = QByteArray("\xEF\xBB\xBF") + "Seat,Key,Place\r\n"
                               "01,vpn://AAA_b-1,Center\r\n"
                               "\"7\";\"vpn://CCC\"\r\n"
                               "8\tvpn://DDD\n"
                               ",vpn://EEE\n"
                               "9,\n";
        const auto table = KeyTableController::parseTable(csv);
        QCOMPARE(table.size(), 3);
        QCOMPARE(table.value(1), QStringLiteral("vpn://AAA_b-1"));
        QCOMPARE(table.value(7), QStringLiteral("vpn://CCC"));
        QCOMPARE(table.value(8), QStringLiteral("vpn://DDD"));
    }

    void testSeatOfServer()
    {
        QCOMPARE(KeyTableController::seatOfServer(awgServerJson("203.0.113.10", "10.8.1.7", tableUrl)), 7);

        QJsonObject withSeat = awgServerJson("203.0.113.10", "10.8.1.7", tableUrl);
        withSeat.insert("key_table_seat", "12");
        QCOMPARE(KeyTableController::seatOfServer(withSeat), 12);

        QCOMPARE(KeyTableController::seatOfServer(QJsonObject {}), 0);
    }

    void testApplyTableReplacesChangedKey()
    {
        importKey(vpnKey(awgServerJson("203.0.113.10", "10.8.1.7", tableUrl)));
        QCOMPARE(m_coreController->m_serversRepository->serversCount(), 1);

        const QString newKey = vpnKey(awgServerJson("203.0.113.20", "10.8.1.7", tableUrl));
        const QByteArray csv = "N,Key\n07," + newKey.toLatin1() + "\n08," + vpnKey(awgServerJson("203.0.113.20", "10.8.1.8", tableUrl)).toLatin1() + "\n";

        QSignalSpy editedSpy(m_coreController->m_serversRepository, &SecureServersRepository::serverEdited);
        QVERIFY(m_coreController->m_keyTableController->applyTable(tableUrl, csv));
        QCOMPARE(editedSpy.count(), 1);
        QCOMPARE(hostOfServer(0), QStringLiteral("203.0.113.20"));
        QCOMPARE(m_coreController->m_serversRepository->serversCount(), 1);

        QVERIFY(!m_coreController->m_keyTableController->applyTable(tableUrl, csv));
        QCOMPARE(editedSpy.count(), 1);
    }

    void testApplyTableRejectsKeyOfAnotherSeat()
    {
        importKey(vpnKey(awgServerJson("203.0.113.10", "10.8.1.7", tableUrl)));

        const QByteArray csv = "7," + vpnKey(awgServerJson("203.0.113.20", "10.8.1.8", tableUrl)).toLatin1() + "\n";
        QVERIFY(!m_coreController->m_keyTableController->applyTable(tableUrl, csv));
        QCOMPARE(hostOfServer(0), QStringLiteral("203.0.113.10"));
    }

    void testApplyTableIgnoresOtherServers()
    {
        importKey(vpnKey(awgServerJson("203.0.113.10", "10.8.1.7", QString())));

        const QByteArray csv = "7," + vpnKey(awgServerJson("203.0.113.20", "10.8.1.7", tableUrl)).toLatin1() + "\n";
        QVERIFY(!m_coreController->m_keyTableController->applyTable(tableUrl, csv));
        QCOMPARE(hostOfServer(0), QStringLiteral("203.0.113.10"));
    }

    void testApplyTableKeepsUrlWhenNewKeyHasNone()
    {
        importKey(vpnKey(awgServerJson("203.0.113.10", "10.8.1.7", tableUrl)));

        const QByteArray csv = "7," + vpnKey(awgServerJson("203.0.113.30", "10.8.1.7", QString())).toLatin1() + "\n";
        QVERIFY(m_coreController->m_keyTableController->applyTable(tableUrl, csv));

        const QString serverId = m_coreController->m_serversRepository->serverIdAt(0);
        QCOMPARE(m_coreController->m_serversRepository->serverJsonById(serverId)->value("key_table_url").toString(), tableUrl);
        QCOMPARE(hostOfServer(0), QStringLiteral("203.0.113.30"));
    }
};

QTEST_MAIN(TestKeyTable)
#include "testKeyTable.moc"
