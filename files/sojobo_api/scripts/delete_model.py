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
import sys
import traceback
import logging
import hashlib
from juju import tag
from juju.client import client
from juju.model import Model
from juju.controller import Controller
from juju.errors import JujuAPIError, JujuError
sys.path.append('/opt')
from sojobo_api import settings  #pylint: disable=C0413
from sojobo_api.api import w_datastore as datastore, w_juju as juju  #pylint: disable=C0413



async def delete_model(c_name, m_name, m_key, usr, pwd):
    try:
        # Get required information from database
        auth_data = datastore.get_model_connection_info(usr, c_name, m_key)
        logger.info(auth_data)

        # Controller_Connection
        logger.info('Setting up Controllerconnection for %s', c_name)
        controller_connection = Controller()
        await controller_connection.connect(auth_data['controller']['endpoints'][0], auth_data['user']['juju_username'], pwd, auth_data['controller']['ca_cert'])

        # Remove A Model
        model_facade = client.ModelManagerFacade.from_connection(controller_connection.connection)
        await model_facade.DestroyModels([client.Entity(tag.model(auth_data['model']['uuid']))])

        # Destroy modle from datastore
        datastore.delete_model(c_name, m_key)
        await controller_connection.disconnect()
        logger.info('%s -> succesfully Destroyed model', m_name)
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)
        #datastore.set_model_state(m_key, 'deleting with error: {}'.format(lines))
    finally:
        if 'controller_connection' in locals():
            await juju.disconnect(controller_connection)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger('delete_model')
    ws_logger = logging.getLogger('websockets.protocol')
    hdlr = logging.FileHandler('{}/log/delete_model.log'.format(settings.SOJOBO_API_DIR))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    ws_logger.addHandler(hdlr)
    ws_logger.setLevel(logging.DEBUG)
    logger.setLevel(logging.DEBUG)
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    loop.run_until_complete(delete_model(sys.argv[1], sys.argv[2], sys.argv[3],
                                             sys.argv[4], sys.argv[5]))
    loop.close()
