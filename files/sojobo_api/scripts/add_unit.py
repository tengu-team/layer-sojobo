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
import json
from juju.client import client
from juju.model import Model
from juju.placement import parse as parse_placement
sys.path.append('/opt')
from sojobo_api import settings
from sojobo_api.api.storage import w_datastore as datastore
from sojobo_api.api import w_juju as juju


async def add_unit(username, password, c_name, m_key, app_name, amount, target):
    try:
        auth_data = datastore.get_model_connection_info(username, c_name, m_key)
        model_connection = Model()
        logger.info('Setting up Model connection for %s:%s', c_name, auth_data['model']['name'])
        await model_connection.connect(auth_data['controller']['endpoints'][0], auth_data['model']['uuid'], auth_data['user']['juju_username'], password, auth_data['controller']['ca_cert'])
        logger.info('Model connection was successful')
        app_facade = client.ApplicationFacade.from_connection(model_connection.connection)
        if target == 'None':
            target = None
        await app_facade.AddUnits(application=app_name,
                                  placement=parse_placement(target),
                                  num_units=int(amount))
        logger.info('Units added to application %s', app_name)
        await model_connection.disconnect()
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)
    finally:
        if 'mod_con' in locals():
            await juju.disconnect(model_connection)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    ws_logger = logging.getLogger('websockets.protocol')
    logger = logging.getLogger('add_unit')
    hdlr = logging.FileHandler('{}/log/add_unit.log'.format(settings.SOJOBO_API_DIR))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    ws_logger.addHandler(hdlr)
    ws_logger.setLevel(logging.DEBUG)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    loop.run_until_complete(add_unit(sys.argv[1], sys.argv[2], sys.argv[3],
                                     sys.argv[4], sys.argv[5],sys.argv[6],sys.argv[7]))
    loop.close()
