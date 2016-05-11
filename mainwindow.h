#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <stdio.h>

#include "sniffer-utils/sniffer.h"

#include <QMainWindow>
#include <QTableWidget>
#include <QString>
#include <QDebug>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

public slots:

private slots:
    void PullPackets(QList<PacketBase>*);
    void AddItem(PacketBase*);

    void on_radioAll_clicked();

    void on_radioIP_clicked();

    void on_radioARP_clicked();

    void on_tableWidget_itemClicked(QTableWidgetItem *item);

signals:
    void PacketsRequested(int);


private:
    Ui::MainWindow *ui;
    Sniffer *sniffer;

    void InitSniffer();
    void InitTableView();
};

#endif // MAINWINDOW_H
