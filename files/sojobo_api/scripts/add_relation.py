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
from juju.errors import JujuAPIError

sys.path.append('/opt')
from sojobo_api import settings
from sojobo_api.api.storage import w_datastore as datastore
from sojobo_api.api import w_juju as juju


async def add_relation(endpoint, ca_cert, model_uuid, juju_username, password,
                       relation1, relation2):
    try:
        logger.info('Setting up Model connection for %s.', model_uuid)
        model_connection = Model()
        await model_connection.connect(endpoint, model_uuid, juju_username,
                                       password, ca_cert)
        logger.info('Model connection was successful.')

        app_facade = client.ApplicationFacade.from_connection(model_connection.connection)

        try:
            await app_facade.AddRelation([relation1, relation2])
            logger.info('Relation %s <-> %s succesfully created!', relation1, relation2)
        except JujuAPIError as e:
            if 'ambiguous relation' in e.message:
                logger.info('Relation %s <-> %s is ambiguous and cannot be added.', relation1, relation2)
            if 'relation already exists' in e.message:
                logger.info('Relation %s <-> %s already exists', relation1, relation2)
            else:
                raise

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
    logger = logging.getLogger('add_relation')
    hdlr = logging.FileHandler('{}/log/add_relation.log'.format(settings.SOJOBO_API_DIR))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    ws_logger.addHandler(hdlr)
    ws_logger.setLevel(logging.DEBUG)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    loop.run_until_complete(add_relation(sys.argv[1], sys.argv[2], sys.argv[3],
                                         sys.argv[4], sys.argv[5], sys.argv[6],
                                         sys.argv[7]))
    loop.close()
