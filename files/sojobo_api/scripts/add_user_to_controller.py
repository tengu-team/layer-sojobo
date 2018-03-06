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
from juju import tag, errors
from juju.client import client
from juju.controller import Controller
sys.path.append('/opt')
from sojobo_api import settings  #pylint: disable=C0413
from sojobo_api.api import w_datastore as datastore, w_juju as juju  #pylint: disable=C0413

################################################################################
# Async method
################################################################################
async def add_user_to_controller(username, password, controller, juju_username):
    try:
        logger.info('adding user %s to controller %s', username, controller)
        con = datastore.get_controller(controller)
        logger.info('Setting up Controllerconnection for %s', con['name'])
        controller_connection = Controller()
        await controller_connection.connect(endpoint=con['endpoints'][0], username=settings.JUJU_ADMIN_USER, password=settings.JUJU_ADMIN_PASSWORD, cacert=con['ca_cert'])
        logger.info('Controller connection as admin was successful')
        user_facade = client.UserManagerFacade.from_connection(controller_connection.connection)
        users = [client.AddUser(display_name=juju_username,
                                username=juju_username,
                                password=password)]
        await user_facade.AddUser(users)
        # grant login access
        # controller_facade = client.ControllerFacade.from_connection(controller_connection.connection)
        # user = tag.user(juju_username)
        # changes = client.ModifyControllerAccess('login', 'grant', user)
        # try:
        #     await controller_facade.ModifyControllerAccess([changes])
        #     return True
        # except errors.JujuError as e:
        #     if 'user already has' in str(e):
        #         return False
        #     else:
        #         raise
        datastore.add_user_to_controller(con['name'], username, 'login')
        logger.info('Succesfully added user %s to controller %s', username, con['name'])
        datastore.set_user_state(username, 'ready')
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger('create_user')
    ws_logger = logging.getLogger('websockets.protocol')
    hdlr = logging.FileHandler('{}/log/create_user.log'.format(settings.SOJOBO_API_DIR))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    ws_logger.addHandler(hdlr)
    ws_logger.setLevel(logging.DEBUG)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    loop.run_until_complete(add_user_to_controller(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]))
    loop.close()
