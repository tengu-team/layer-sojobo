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
import traceback
import logging
import sys
sys.path.append('/opt')  # noqa: E402

from juju import tag
from juju.client import client
from juju.controller import Controller

from sojobo_api import settings
from sojobo_api.api.storage import w_datastore as datastore
from sojobo_api.api import w_juju as juju


async def change_password(controller_name, juju_username, password):
    """
    This script will change the user his password on the given controller.

    :param juju_username: The username as it is known by JUJU, not the same as
        the username to log in.
    :type juju_username: str.
    :param password: The new password for the provided user.
    :type password: str.
    :param controller_name: The name of the controller where the password needs
        to be changed
    :type controller_name: str.
    """
    try:
        logger.info('Setting up Controller connection for %s.',
                    controller_name)
        controller = datastore.get_controller(controller_name)
        controller_connection = Controller()
        await controller_connection.connect(
                    endpoint=controller['endpoint'][0],
                    username=settings.JUJU_ADMIN_USER,
                    password=settings.JUJU_ADMIN_PASSWORD,
                    cacert=controller['ca-cert'])
        logger.info('Controller connection as admin was successful.')

        logger.info('Initializing user manager facade...')
        user_facade = client.UserManagerFacade.from_connection(
                            controller_connection.connection)
        entity = client.EntityPassword(password, tag.user(juju_username))

        logger.info('Changing password...')
        await user_facade.SetPassword([entity])
        logger.info('Changed password!')

    except Exception:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)
    finally:
        if 'controller_connection' in locals():
            await juju.disconnect(controller_connection)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    ws_logger = logging.getLogger('websockets.protocol')
    logger = logging.getLogger('change_password')
    hdlr = logging.FileHandler(
                '{}/log/change_password.log'.format(settings.SOJOBO_API_DIR))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    ws_logger.addHandler(hdlr)
    ws_logger.setLevel(logging.DEBUG)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    result = loop.run_until_complete(change_password(sys.argv[1], sys.argv[2],
                                                     sys.argv[3]))
    loop.close()
