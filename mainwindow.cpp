#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    InitTableView();
    InitSniffer();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::AddItem(const char *buffer)
{
    int count = ui->tableWidget->rowCount();

    char num_buffer [50];
    sprintf(num_buffer, "%d", count + 1);
    QString str = QString::fromUtf8(num_buffer);

    ui->tableWidget->insertRow(count);
    ui->tableWidget->setItem(count, 0, new QTableWidgetItem(str));
    ui->tableWidget->setItem(count, 3, new QTableWidgetItem(buffer));
}

void MainWindow::InitSniffer()
{
    sniffer = new Sniffer();
    sniffer->moveToThread(sniffer);
    sniffer->start();
    connect(sniffer, SIGNAL(PacketRecieved(const char*)), this, SLOT(AddItem(const char*)));
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

