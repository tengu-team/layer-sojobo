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
import sys
import traceback
import logging
from juju import tag, errors
from juju.client import client
from juju.controller import Controller
sys.path.append('/opt')
from sojobo_api import settings  #pylint: disable=C0413
from sojobo_api.api import w_datastore as datastore, w_juju as juju  #pylint: disable=C0413

async def change_password(c_name, juju_username, password):
    try:
        controller_ds = datastore.get_controller(c_name)
        #user_ds = datastore.get_user(username)

        logger.info('Setting up Controller connection for %s.', controller_ds['name'])
        controller_connection = Controller()
        await controller_connection.connect(endpoint=controller_ds['endpoints'][0],
                                            username=settings.JUJU_ADMIN_USER,
                                            password=settings.JUJU_ADMIN_PASSWORD,
                                            cacert=controller_ds['ca_cert'])
        logger.info('Controller connection as admin was successful.')

        logger.info('Initializing user manager facade...')
        user_facade = client.UserManagerFacade.from_connection(controller_connection.connection)
        entity = client.EntityPassword(password, tag.user(juju_username))

        logger.info('Changing password...')
        await user_facade.SetPassword([entity])
        logger.info('Password has been changed!')

    except Exception:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)
    finally:
        await juju.disconnect(controller_connection)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    ws_logger = logging.getLogger('websockets.protocol')
    logger = logging.getLogger('change_password')
    hdlr = logging.FileHandler('{}/log/change_password.log'.format(settings.SOJOBO_API_DIR))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    ws_logger.addHandler(hdlr)
    ws_logger.setLevel(logging.DEBUG)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    result = loop.run_until_complete(set_controller_acc(sys.argv[1], sys.argv[2],
                                                        sys.argv[3]))
    loop.close()
