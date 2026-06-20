#!/usr/bin/env python
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand
from main import app, db

manager = Manager(app)

migrate = Migrate(app, db)

manager.add_command("db", MigrateCommand)

if __name__ == "__main__":
    manager.run()
