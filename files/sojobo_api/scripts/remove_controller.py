# !/usr/bin/env python3
# Copyright (C) 2017  Qrama
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# pylint: disable=c0111,c0301,c0325,c0103,r0913,r0902,e0401,C0302, R0914
import logging
import subprocess as sp
import traceback
import sys
sys.path.append('/opt')
from sojobo_api import settings  #pylint: disable=C0413
from sojobo_api.api import w_datastore as datastore#pylint: disable=C0413


def remove_controller(name, c_type):
    try:
        logger.info('Removing controller %s', name)
        sp.check_output(['juju', 'login', '-c', name, '-u', settings.JUJU_ADMIN_USER], input=bytes('{}\n'.format(settings.JUJU_ADMIN_PASSWORD), 'utf-8'))
        sp.check_call(['juju', 'destroy-controller', '-y', name, '--destroy-all-models'])
        logger.info('Removing controller %s from Datastore', name)
        sp.check_call(['juju', 'remove-credential', c_type, name])
        datastore.destroy_controller(name)
        logger.info('Succesfully removed controller %s!', name)
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)

if __name__ == '__main__':
    logger = logging.getLogger('remove-controller')
    hdlr = logging.FileHandler('{}/log/remove_controller.log'.format(settings.SOJOBO_API_DIR))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    remove_controller(sys.argv[1], sys.argv[2])
