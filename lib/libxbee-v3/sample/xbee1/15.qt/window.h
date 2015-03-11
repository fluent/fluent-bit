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

#ifndef WINDOW_H
#define WINDOW_H

#include <QDialog>
#include <QLineEdit>
#include <QPushButton>

#include "xbeeqt.h"

namespace Ui {
	class window;
}

class window: public QDialog {
		Q_OBJECT

	public:
		explicit window(QWidget *parent = 0);
		~window();

	private:
		Ui::window *ui;

		QLineEdit *ui_textIdent;
		QPushButton *ui_btnGet;
		QPushButton *ui_btnSet;

		enum {
			STATE_READY1,
			STATE_READY2,
			STATE_RETRIEVING,
			STATE_SENDING,
			STATE_ERROR,
		} state;

		libxbee::XBee *t_xbee;
		libxbee::ConQt *t_con;

		void setEnabled(bool enabled);

	public slots:
		void triggerGet(bool checked);

	private slots:
		void triggerSet(bool checked);
		void textIdentChanged(const QString &text);
		void response(libxbee::Pkt *pkt);
};

#endif // WINDOW_H
