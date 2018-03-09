
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
import ast
import sys
import traceback
import logging
from juju import tag, errors
from juju.client import client
from juju.model import Model
sys.path.append('/opt')
from sojobo_api import settings  #pylint: disable=C0413
from sojobo_api.api import w_datastore as datastore, w_juju as juju  #pylint: disable=C0413


async def update_ssh_key(ssh_keys, username):
    try:
        user_info = datastore.get_user_info(username)
        juju_username = user_info["juju_username"]
        current_keys = user_info["ssh_keys"]
        new_keys = ast.literal_eval(ssh_keys)

        for controller in user_info["controllers"]:
            endpoint = controller["endpoints"][0]
            cacert = controller["ca_cert"]

            for model in controller['models']:
                mod_access = model["access"]
                uuid = model["uuid"]
                if mod_access == 'write' or mod_access == 'admin':

                    logger.info('Setting up model connection for model: %s', model)
                    model_connection = Model()
                    await model_connection.connect(endpoint, uuid, juju_username, password, cacert=cacert)
                    logger.info('Model connection was successful.')

                    logger.info('Initializing KeyManagerFacade...')
                    key_facade = client.KeyManagerFacade.from_connection(model_connection)

                    logger.info('Removing current ssh keys...')
                    for key in current_keys:
                        logger.info('removing key: %s', key)
                        await key_facade.DeleteKeys([key], user)

                    logger.info('Adding new ssh keys...')
                    for key in new_keys:
                        logger.info('adding key: %s', key)
                        await key_facade.AddKeys([key], juju_username)

        logger.info('Updating ssh keys in database...')
        datastore.update_ssh_keys(username, new_keys)
        logger.info('Updated SSH keys!')

    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    ws_logger = logging.getLogger('websockets.protocol')
    logger = logging.getLogger('remove_ssh_keys')
    hdlr = logging.FileHandler('{}/log/update_ssh_keys.log'.format(sys.argv[3]))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    ws_logger.addHandler(hdlr)
    ws_logger.setLevel(logging.DEBUG)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    result = loop.run_until_complete(update_ssh_key(sys.argv[1], sys.argv[2]))
    loop.close()
