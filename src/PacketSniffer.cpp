#include "PacketSniffer.h"
#include <QHostAddress>
#include <QDebug>
#include <arpa/inet.h>

PacketSniffer::PacketSniffer(QObject *parent) : QThread(parent) {}

PacketSniffer::~PacketSniffer() {
    stopCapture();
}

bool PacketSniffer::startCapture(const QString &device, const QString &filterExp) {
    deviceName = device;
    filterExpression = filterExp;
    capturing = true;
    start();
    return true;
}

void PacketSniffer::stopCapture() {
    capturing = false;
    if (handle) {
        pcap_breakloop(handle);
        pcap_close(handle);
        handle = nullptr;
    }
    wait();
}

void PacketSniffer::run() {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(deviceName.toStdString().c_str(), 65536, 1, 1000, errbuf);
    if (!handle) {
        qWarning() << "Couldn't open device:" << deviceName << errbuf;
        return;
    }

    if (!filterExpression.isEmpty()) {
        struct bpf_program filter;
        if (pcap_compile(handle, &filter, filterExpression.toStdString().c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            qWarning() << "Bad filter:" << filterExpression;
        } else {
            pcap_setfilter(handle, &filter);
            pcap_freecode(&filter);
        }
    }

    pcap_loop(handle, 0, packetHandler, reinterpret_cast<u_char*>(this));
}

void PacketSniffer::packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    PacketSniffer *sniffer = reinterpret_cast<PacketSniffer*>(userData);
    if (sniffer->capturing) {
        sniffer->processPacket(pkthdr, packet);
    }
}

void PacketSniffer::processPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    const int ethernetHeaderLength = 14;
    if (pkthdr->caplen < ethernetHeaderLength + sizeof(struct ip)) return;

    const struct ip* ipHeader = (struct ip*)(packet + ethernetHeaderLength);
    QString srcIP = QHostAddress(ntohl(ipHeader->ip_src.s_addr)).toString();
    QString dstIP = QHostAddress(ntohl(ipHeader->ip_dst.s_addr)).toString();

    PacketData pkt;
    pkt.srcIP = srcIP;
    pkt.dstIP = dstIP;
    pkt.srcPort = 0;
    pkt.dstPort = 0;

    if (ipHeader->ip_p == IPPROTO_TCP) {
        pkt.protocol = "TCP";
        const struct tcphdr* tcpHeader = (struct tcphdr*)(packet + ethernetHeaderLength + ipHeader->ip_hl * 4);
        pkt.srcPort = ntohs(tcpHeader->th_sport);
        pkt.dstPort = ntohs(tcpHeader->th_dport);
        int headerSize = ethernetHeaderLength + ipHeader->ip_hl * 4 + tcpHeader->th_off * 4;
        int payloadSize = pkthdr->caplen - headerSize;
        if (payloadSize > 0) {
            pkt.payload = QByteArray((const char*)(packet + headerSize), payloadSize);
        }
    } else if (ipHeader->ip_p == IPPROTO_UDP) {
        pkt.protocol = "UDP";
        const struct udphdr* udpHeader = (struct udphdr*)(packet + ethernetHeaderLength + ipHeader->ip_hl * 4);
        pkt.srcPort = ntohs(udpHeader->uh_sport);
        pkt.dstPort = ntohs(udpHeader->uh_dport);
        int headerSize = ethernetHeaderLength + ipHeader->ip_hl * 4 + sizeof(struct udphdr);
        int payloadSize = pkthdr->caplen - headerSize;
        if (payloadSize > 0) {
            pkt.payload = QByteArray((const char*)(packet + headerSize), payloadSize);
        }
    } else {
        pkt.protocol = QString("Other (%1)").arg(ipHeader->ip_p);
    }

    emit packetCaptured(pkt);
}