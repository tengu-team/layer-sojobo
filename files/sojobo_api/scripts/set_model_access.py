#!/usr/bin/env python3
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
import ast
import traceback
import logging
from juju import tag, errors
from juju.client import client
from juju.controller import Controller
sys.path.append('/opt')
from sojobo_api import settings  #pylint: disable=C0413
from sojobo_api.api import w_datastore as datastore, w_juju as juju  #pylint: disable=C0413
from juju.errors import JujuAPIError, JujuError


async def set_model_acc(username, c_name, endpoint, cacert, m_key, uuid, access):
    try:
        user_info = datastore.get_user_info(username)
        print(user_info)
        juju_username = user_info["juju_username"]
        ssh_keys = user_info["ssh_keys"]

        logger.info('Setting up Controller connection for %s.', c_name)
        controller_connection = Controller()
        await controller_connection.connect(endpoint=endpoint,
                                            username=settings.JUJU_ADMIN_USER,
                                            password=settings.JUJU_ADMIN_PASSWORD,
                                            cacert=cacert)
        logger.info('Controller connection as admin was successful.')

        logger.info('setting Model Access for %s on %s!', juju_username, m_key)
        current_access = datastore.get_model_and_access(m_key, username)
        logger.info('Current Access level: %s', current_access)

        model_facade = client.ModelManagerFacade.from_connection(
                        controller_connection.connection)
        user = tag.user(juju_username)
        model = tag.model(uuid)

        print("Current access:")
        print(current_access)

        if current_access["m_access"]:
            changes = client.ModifyModelAccess('read', 'revoke', model, user)
            await model_facade.ModifyModelAccess([changes])

        changes = client.ModifyModelAccess(access, 'grant', model, user)
        await model_facade.ModifyModelAccess([changes])

        if access in ['admin', 'write']:
            juju.update_ssh_keys_model(username, ssh_keys, c_name, m_key)

        datastore.set_model_access(m_key, username, access)
        logger.info('Model Access set for %s on %s!', username, m_key)

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
    logger = logging.getLogger('set_model_access')
    hdlr = logging.FileHandler('{}/log/set_model_access.log'.format(settings.SOJOBO_API_DIR))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    ws_logger.addHandler(hdlr)
    ws_logger.setLevel(logging.DEBUG)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    result = loop.run_until_complete(set_model_acc(sys.argv[1], sys.argv[2],
                                                   sys.argv[3], sys.argv[4],
                                                   sys.argv[5], sys.argv[6],
                                                   sys.argv[7]))
    loop.close()
