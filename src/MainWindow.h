#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStandardItemModel>
#include "PacketSniffer.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onPacketCaptured(const PacketData &packet);

private:
    PacketSniffer *sniffer;
    QStandardItemModel *model;
};

#endif // MAINWINDOW_H