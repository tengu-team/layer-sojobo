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
from juju.client import client
from juju.controller import Controller
sys.path.append('/opt')
from sojobo_api import settings  #pylint: disable=C0413
from sojobo_api.api import w_datastore as datastore, w_juju as juju  #pylint: disable=C0413

################################################################################
# Async method
################################################################################
async def add_user_to_controller(username, password, juju_username, c_name, endpoint, cacert):
    try:
        logger.info('Adding user %s to controller %s...', username, c_name)
        logger.info('Setting up Controller connection for %s...', c_name)
        controller_connection = Controller()
        await controller_connection.connect(endpoint=endpoint,
                                            username=settings.JUJU_ADMIN_USER,
                                            password=settings.JUJU_ADMIN_PASSWORD,
                                            cacert=cacert)
        logger.info('Controller connection as admin was successful.')

        user_facade = client.UserManagerFacade.from_connection(controller_connection.connection)
        users = [client.AddUser(display_name=juju_username,
                                username=juju_username,
                                password=password)]
        await user_facade.AddUser(users)

        logger.info('%s -> Adding credentials', c_name)
        controller = datastore.get_controller(c_name)
        await juju.update_cloud(controller_connection, controller['type'], controller['default-credential'], juju_username, settings.JUJU_ADMIN_USER)

        datastore.add_user_to_controller(c_name, username, 'login')
        logger.info('Succesfully added user %s to controller %s!', username, c_name)
        datastore.set_user_state(username, 'ready')
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)
    finally:
        if 'controller_connection' in locals():
            await controller_connection.disconnect()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger('add_user_to_controller')
    ws_logger = logging.getLogger('websockets.protocol')
    hdlr = logging.FileHandler('{}/log/add_user_to_controller.log'.format(settings.SOJOBO_API_DIR))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    ws_logger.addHandler(hdlr)
    ws_logger.setLevel(logging.DEBUG)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    loop.run_until_complete(add_user_to_controller(sys.argv[1], sys.argv[2],
                                                   sys.argv[3], sys.argv[4],
                                                   sys.argv[5], sys.argv[6]))
    loop.close()
