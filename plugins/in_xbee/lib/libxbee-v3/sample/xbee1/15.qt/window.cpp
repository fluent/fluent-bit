/*
	libxbee - a C/C++ library to aid the use of Digi's XBee wireless modules
	          running in API mode.

	Copyright (C) 2009 onwards  Attie Grande (attie@attie.co.uk)

	libxbee is free software: you can redistribute it and/or modify it
	under the terms of the GNU Lesser General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	libxbee is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
	GNU Lesser General Public License for more details.

	You should have received a copy of the GNU Lesser General Public License
	along with libxbee. If not, see <http://www.gnu.org/licenses/>.
*/

#include "window.h"
#include "ui_window.h"

window::window(QWidget *parent): QDialog(parent), ui(new Ui::window) {
	ui->setupUi(this);

	if ((ui_textIdent = this->findChild<QLineEdit*>("textIdent")) == NULL) throw(-1);
	if ((ui_btnGet = this->findChild<QPushButton*>("btnGet")) == NULL) throw(-1);
	if ((ui_btnSet = this->findChild<QPushButton*>("btnSet")) == NULL) throw(-1);

	if ((t_xbee = new libxbee::XBee("xbee1", "/dev/ttyUSB0", 57600)) == NULL) throw(-1);
	if ((t_con = new libxbee::ConQt(*t_xbee, "Local AT")) == NULL) throw(-1);
	connect(t_con, SIGNAL(Rx(libxbee::Pkt*)), this, SLOT(response(libxbee::Pkt*)));

	state = STATE_READY1;

	connect(ui_textIdent, SIGNAL(textChanged(const QString&)), this, SLOT(textIdentChanged(const QString &)));
	connect(ui_btnGet, SIGNAL(clicked(bool)), this, SLOT(triggerGet(bool)));
	connect(ui_btnSet, SIGNAL(clicked(bool)), this, SLOT(triggerSet(bool)));
}

window::~window() {
    delete ui;
}

/* --- */

void window::setEnabled(bool enabled) {
	ui_textIdent->setEnabled(enabled);
	ui_btnSet->setEnabled(enabled);
	ui_btnGet->setEnabled(enabled);
}

void window::textIdentChanged(const QString &text) {
	disconnect(ui_textIdent, SIGNAL(textChanged(const QString&)), this, SLOT(textIdentChanged(const QString &)));
	ui_btnSet->setEnabled(true);
	state = STATE_READY2;
}

void window::triggerGet(bool checked) {
	setEnabled(false);
	state = STATE_RETRIEVING;

	t_con->Tx("NI");
}

void window::triggerSet(bool checked) {
	setEnabled(false);
	state = STATE_SENDING;

	QString str("NI");
	str += ui_textIdent->text();
	
	t_con->Tx(str.toLatin1().data());
}

void window::response(libxbee::Pkt *pkt) {
	switch (state) {
		case STATE_RETRIEVING:
			{
				std::string str((const char*)(pkt->getHnd()->data));
				QString qstr(str.c_str());
				ui_textIdent->setText(qstr);
				state = STATE_READY2;
				setEnabled(true);
			}
			break;
		case STATE_SENDING:
			state = STATE_READY2;
			setEnabled(true);
			break;
		default:;
	}

	delete pkt;
}
