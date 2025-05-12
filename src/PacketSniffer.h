#ifndef PACKETSNIFFER_H
#define PACKETSNIFFER_H

#include <QObject>
#include <QThread>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

struct PacketData {
    QString srcIP;
    QString dstIP;
    QString protocol;
    quint16 srcPort;
    quint16 dstPort;
    QByteArray payload;
};

class PacketSniffer : public QThread
{
    Q_OBJECT
public:
    explicit PacketSniffer(QObject *parent = nullptr);
    ~PacketSniffer();

    bool startCapture(const QString &device, const QString &filterExp = "");
    void stopCapture();

signals:
    void packetCaptured(const PacketData &packet);

protected:
    void run() override;

private:
    pcap_t *handle = nullptr;
    bool capturing = false;
    QString filterExpression;
    QString deviceName;

    static void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    void processPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet);
};

#endif // PACKETSNIFFER_H