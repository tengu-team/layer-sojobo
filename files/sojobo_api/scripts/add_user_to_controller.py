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
import asyncio
import logging
import sys
import traceback
sys.path.append('/opt')  # noqa: E402

from juju.client import client
from juju.controller import Controller

from sojobo_api import settings
from sojobo_api.api.storage import w_datastore as datastore
from sojobo_api.api import w_juju as juju


async def add_user_to_controller(username, password,
                                 juju_username, controller_key):
    try:
        logger.info('Adding user %s to controller %s...', username, controller_key)
        logger.info('Setting up Controller connection for %s...', controller_key)
        controller = datastore.get_controller(controller_key)
        controller_connection = Controller()
        await controller_connection.connect(
                    endpoint=controller['endpoint'],
                    username=settings.JUJU_ADMIN_USER,
                    password=settings.JUJU_ADMIN_PASSWORD,
                    cacert=controller['ca-cert'])
        logger.info('Controller connection as admin was successful.')

        user_facade = client.UserManagerFacade.from_connection(
                    controller_connection.connection)
        users = [client.AddUser(display_name=juju_username,
                                username=juju_username,
                                password=password)]
        await user_facade.AddUser(users)

        logger.info('%s -> Adding credentials', controller_key)

        await juju.update_cloud(controller_connection, controller['type'],
                                controller['default-credential'],
                                juju_username, settings.JUJU_ADMIN_USER)

        datastore.add_user_to_controller(controller_key, username, 'login')
        logger.info('Succesfully added user %s to controller %s!',
                    username, controller_key)
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
    hdlr = logging.FileHandler('{}/log/add_user_to_controller.log'.format(
                settings.SOJOBO_API_DIR))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    ws_logger.addHandler(hdlr)
    ws_logger.setLevel(logging.DEBUG)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    loop.run_until_complete(add_user_to_controller(sys.argv[1], sys.argv[2],
                                                   sys.argv[3], sys.argv[4]))
    loop.close()
