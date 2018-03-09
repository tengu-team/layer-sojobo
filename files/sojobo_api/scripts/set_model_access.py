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
from sojobo_api.api import w_datastore as datastore, w_juju as juju  #pylint: disable=C0413
from juju.errors import JujuAPIError, JujuError


async def set_model_acc(juju_username, password, controller, model, access):
    try:
        access_list = ast.literal_eval(models_access)
        ssh_keys = datastore.get_ssh_keys(username)
        endpoint = controller["endpoints"][0]
        cacert = controller["ca_cert"]
        m_name = model["name"]
        m_key = model["_key"]
        uuid = model["uuid"]

        logger.info('Setting up Controller connection for %s.', c_name)
        controller_connection = Controller()
        await controller_connection.connect(endpoint=endpoint,
                                            username=settings.JUJU_ADMIN_USER,
                                            password=settings.JUJU_ADMIN_PASSWORD,
                                            cacert=cacert)
        logger.info('Controller connection as admin was successful.')

        logger.info('setting Model Access for %s on %s!', juju_username, m_name)
        current_access = datastore.get_model_and_access(mod['_key'], user)
        logger.info('Current Access level: %s', current_access)

        model_facade = client.ModelManagerFacade.from_connection(
                        controller_connection.connection)
        user = tag.user(juju_username)
        model = tag.model(uuid)

        if current_access:
            changes = client.ModifyModelAccess('read', 'revoke', model, user)
            await model_facade.ModifyModelAccess([changes])

        changes = client.ModifyModelAccess(acl, 'grant', model, user)
        await model_facade.ModifyModelAccess([changes])

        if mod['access'] in ['admin', 'write']:
            juju.update_ssh_keys_user(username, ssh_keys)

        datastore.set_model_access(m_key, user, mod['access'])
        logger.info('Model Access set for %s on %s!', user, mod['name'])
    except Exception:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    ws_logger = logging.getLogger('websockets.protocol')
    logger = logging.getLogger('set_model_access')
    hdlr = logging.FileHandler('{}/log/set_model_access.log'.format(settings.SOJOBO_API_DIR,))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    ws_logger.addHandler(hdlr)
    ws_logger.setLevel(logging.DEBUG)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    result = loop.run_until_complete(set_model_acc(sys.argv[1], sys.argv[2],
                                                   sys.argv[4], sys.argv[5], sys.argv[6]))
    loop.close()
