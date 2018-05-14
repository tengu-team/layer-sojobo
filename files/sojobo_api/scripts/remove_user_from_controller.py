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
from juju import tag
from juju.client import client
from juju.controller import Controller
from sojobo_api import settings  #pylint: disable=C0413
from sojobo_api.api.storage import w_datastore as datastore
from sojobo_api.api import w_juju as juju  #pylint: disable=C0413


################################################################################
# Async method
################################################################################
async def remove_user_from_controller(username, c_name):
    try:
        data = datastore.get_controller_connection_info(username, c_name)

        logger.info('Setting up Controllerconnection for %s', c_name)
        controller_connection = Controller()
        await controller_connection.connect(endpoint=data['controller']['endpoints'][0],
                                            username=settings.JUJU_ADMIN_USER,
                                            password=settings.JUJU_ADMIN_PASSWORD,
                                            cacert=data['controller']['ca_cert'])
        logger.info('Controller connection as admin was successful')

        user_facade = client.UserManagerFacade.from_connection(controller_connection.connection)
        entity = client.Entity(tag.user(data['user']['juju_username']))

        logger.info('Removing user from %s', c_name)
        await user_facade.RemoveUser([entity])
        datastore.delete_user(username)
        logger.info('Removed user %s from Controller %s!', username ,c_name)
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)
    finally:
        if controller_connection in locals():
            await juju.disconnect(controller_connection)

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger('remove_user_from_controller')
    ws_logger = logging.getLogger('websockets.protocol')
    hdlr = logging.FileHandler('{}/log/remove_user_from_controller.log'.format(settings.SOJOBO_API_DIR))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    ws_logger.addHandler(hdlr)
    ws_logger.setLevel(logging.DEBUG)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    loop.run_until_complete(remove_user_from_controller(sys.argv[1], sys.argv[2]))
    loop.close()
