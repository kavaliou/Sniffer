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

private slots:
    void AddItem(PacketBase *packet);

private:    
    Ui::MainWindow *ui;
    Sniffer *sniffer;

    void InitSniffer();
    void InitTableView();
};

#endif // MAINWINDOW_H
