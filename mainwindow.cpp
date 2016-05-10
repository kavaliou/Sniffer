#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    InitSniffer();
    ui->setupUi(this);
    InitTableView();
}

MainWindow::~MainWindow()
{
    delete sniffer;
    delete ui;
}

void MainWindow::PullPackets(QList<PacketBase> *packets) {
    ui->tableWidget->clear();
    ui->tableWidget->setRowCount(0);
    int count = 0;
    QList<PacketBase>::iterator i;
    for (i = packets->begin(); i != packets->end(); ++i){
        char num_buffer [50];
        sprintf(num_buffer, "%d", count + 1);
        QString str = QString::fromUtf8(num_buffer);

        ui->tableWidget->insertRow(count);
        ui->tableWidget->setItem(count, 0, new QTableWidgetItem(str));
        ui->tableWidget->setItem(count, 1, new QTableWidgetItem(i->source));
        ui->tableWidget->setItem(count, 2, new QTableWidgetItem(i->destination));
        ui->tableWidget->setItem(count, 3, new QTableWidgetItem(i->protocol));
        count++;
    }
}

void MainWindow::AddItem(PacketBase *packet)
{
    int count = ui->tableWidget->rowCount();

    char num_buffer [50];
    sprintf(num_buffer, "%d", count + 1);
    QString str = QString::fromUtf8(num_buffer);

    ui->tableWidget->insertRow(count);
    ui->tableWidget->setItem(count, 0, new QTableWidgetItem(str));
    ui->tableWidget->setItem(count, 1, new QTableWidgetItem(packet->source));
    ui->tableWidget->setItem(count, 2, new QTableWidgetItem(packet->destination));
    ui->tableWidget->setItem(count, 3, new QTableWidgetItem(packet->protocol));
}

void MainWindow::InitSniffer()
{
    sniffer = new Sniffer();
    sniffer->moveToThread(sniffer);
    sniffer->start();

    connect(sniffer, SIGNAL(PacketPushed(QList<PacketBase>*)), this, SLOT(PullPackets(QList<PacketBase>*)));
    connect(sniffer, SIGNAL(PacketRecieved(PacketBase*)), this, SLOT(AddItem(PacketBase*)));
    connect(this, SIGNAL(destroyed()), sniffer, SLOT(quit()));
}

void MainWindow::InitTableView()
{
    ui->tableWidget->setRowCount(0);
    ui->tableWidget->setColumnCount(4);
    QStringList m_TableHeader;
    m_TableHeader << "#" << "Source" << "Destination" << "Protocol";
    ui->tableWidget->setHorizontalHeaderLabels(m_TableHeader);
    ui->tableWidget->verticalHeader()->setVisible(false);
    ui->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->tableWidget->setShowGrid(false);
}


void MainWindow::on_radioAll_clicked()
{
    sniffer->GetPackets(0);
}

void MainWindow::on_radioIP_clicked()
{
    sniffer->GetPackets(1);
}

void MainWindow::on_radioARP_clicked()
{
    sniffer->GetPackets(2);
}
