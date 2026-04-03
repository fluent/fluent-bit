#  Fluent Bit
#  ==========
#  Copyright (C) 2015-2024 The Fluent Bit Authors
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import os
import yaml
import logging
import pytest

# Configure logging
def configure_logging():
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger

logger = configure_logging()

def load_global_config():
    config_file = os.path.abspath(os.path.join(os.path.dirname(__file__), 'config.yaml'))
    with open(config_file, 'r') as file:
        return yaml.safe_load(file)

GLOBAL_CONFIG = load_global_config()

@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
    logger.info("Configuring pytest")

@pytest.hookimpl(tryfirst=True)
def pytest_sessionstart(session):
    logger.info("Starting pytest session")
    #flb = FluentBitManager(GLOBAL_CONFIG['fluent_bit']['config_path'])
    #flb = FluentBitManager()

@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    pass #logger.info("Finishing pytest session")

@pytest.hookimpl(trylast=True)
def pytest_unconfigure(config):
    logger.info("Unconfiguring pytest")
