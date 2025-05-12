#include "MainWindow.h"
#include <QTableView>
#include <QVBoxLayout>
#include <pcap.h>
#include <QDebug>

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    model = new QStandardItemModel(this);
    model->setHorizontalHeaderLabels({"Src IP", "Dst IP", "Protocol", "Src Port", "Dst Port", "Payload"});

    QTableView *tableView = new QTableView(this);
    tableView->setModel(model);
    tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);

    QWidget *central = new QWidget(this);
    QVBoxLayout *layout = new QVBoxLayout(central);
    layout->addWidget(tableView);
    setCentralWidget(central);

    sniffer = new PacketSniffer(this);
    connect(sniffer, &PacketSniffer::packetCaptured, this, &MainWindow::onPacketCaptured);

    // Seleciona o primeiro dispositivo disponível para captura
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == 0 && alldevs) {
        QString devName = alldevs->name;
        pcap_freealldevs(alldevs);
        qDebug() << "Starting capture on device:" << devName;
        sniffer->startCapture(devName);
    } else {
        qWarning() << "No devices found or error:" << errbuf;
    }
}

MainWindow::~MainWindow() {
    sniffer->stopCapture();
}

void MainWindow::onPacketCaptured(const PacketData &packet) {
    QList<QStandardItem*> rowItems;
    rowItems << new QStandardItem(packet.srcIP)
             << new QStandardItem(packet.dstIP)
             << new QStandardItem(packet.protocol)
             << new QStandardItem(QString::number(packet.srcPort))
             << new QStandardItem(QString::number(packet.dstPort))
             << new QStandardItem(QString(packet.payload.toHex()));

    model->appendRow(rowItems);
}