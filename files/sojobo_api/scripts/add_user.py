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
import asyncio
import logging
import sys
import traceback
sys.path.append('/opt')
from sojobo_api import settings  #pylint: disable=C0413
from sojobo_api.api import w_datastore as datastore, w_juju as juju  #pylint: disable=C0413


class JuJu_Token(object):  #pylint: disable=R0903
    def __init__(self):
        self.username = settings.JUJU_ADMIN_USER
        self.password = settings.JUJU_ADMIN_PASSWORD
        self.is_admin = True

################################################################################
# Async method
################################################################################
async def create_user(username, password):
    try:
        datastore.create_user(username)
        logger.info('Succesfully created user %s', username)
        controllers = datastore.get_all_controllers()
        token = JuJu_Token()
        for con in controllers:
            logger.info('Setting up Controllerconnection for %s', con)
            controller = juju.Controller_Connection(token, con)
            async with controller.connect(token) as con_juju:  #pylint: disable=E1701
                await con_juju.add_user(username, password)
                await con_juju.grant(username)
                datastore.add_user_to_controller(con, username, 'login')
                logger.info('Succesfully added user %s to controller %s', username, con)
        datastore.set_user_state(username, 'ready')
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger('add-user')
    ws_logger = logging.getLogger('websockets.protocol')
    hdlr = logging.FileHandler('{}/log/add_user.log'.format(settings.SOJOBO_API_DIR))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    ws_logger.addHandler(hdlr)
    ws_logger.setLevel(logging.DEBUG)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    loop.run_until_complete(create_user(sys.argv[1], sys.argv[2]))
    loop.close()
