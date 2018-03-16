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
from sojobo_api.api import w_datastore as datastore, w_juju as juju


async def remove_relation(c_name, endpoint, cacert,  m_name, uuid, juju_username, password,
                       app1, app2):
    try:
        logger.info('Setting up Model connection for %s:%s.', c_name, m_name)
        model_connection = Model()
        await model_connection.connect(endpoint,
                                       uuid,
                                       juju_username,
                                       password,
                                       cacert)
        logger.info('Model connection was successful.')

        logger.info('Getting application entity...')
        entity = juju.get_application_entity(model_connection, app1)
        logger.info('Initializing facade...')
        app_facade = client.ApplicationFacade.from_connection(entity.connection)

        # First param must be name of relation that app1 has with app2. (local relation)
        # Second param is remote relation name.
        await app_facade.DestroyRelation([app2, app1])
        logger.info('Relation %s <-> %s succesfully destroyed!', app1, app2)

        await model_connection.disconnect()
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)
    finally:
        if 'model_connection' in locals():
            await juju.disconnect(model_connection)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    ws_logger = logging.getLogger('websockets.protocol')
    logger = logging.getLogger('remove_relation')
    hdlr = logging.FileHandler('{}/log/remove_relation.log'.format(settings.SOJOBO_API_DIR))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    ws_logger.addHandler(hdlr)
    ws_logger.setLevel(logging.DEBUG)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    loop.run_until_complete(remove_relation(sys.argv[1], sys.argv[2], sys.argv[3],
                                         sys.argv[4], sys.argv[5], sys.argv[6],
                                         sys.argv[7], sys.argv[8], sys.argv[9]))
    loop.close()
