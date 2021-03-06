
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
import json
import sys
import traceback
import logging
import base64, hashlib
from juju import tag, errors
from juju.client import client
from juju.model import Model
sys.path.append('/opt')
from sojobo_api import settings  #pylint: disable=C0413
from sojobo_api.api import w_datastore as datastore, w_juju as juju  #pylint: disable=C0413


async def update_ssh_keys_model(ssh_keys, username, c_name, m_key):
    """Updates the ssh keys of a user on a specific model where the user has admin
    or write access to."""
    try:
        logger.info('Updating SSH keys for model {}...'.format(m_key))
        user_info = datastore.get_user(username)
        juju_username = user_info["juju_username"]
        current_keys = user_info["ssh_keys"]
        json_acceptable_string = ssh_keys.replace("'", "\"")
        new_keys = json.loads(json_acceptable_string)

        controller = datastore.get_controller(c_name)
        endpoint = controller["endpoints"][0]
        cacert = controller["ca_cert"]

        model = datastore.get_model(m_key)
        mod_access = datastore.get_model_access(c_name, model["name"], username)
        uuid = model["uuid"]

        if mod_access == 'write' or mod_access == 'admin':

            logger.info('Setting up model connection for model: %s', model)
            model_connection = Model()
            await model_connection.connect(endpoint, uuid, settings.JUJU_ADMIN_USER,
            settings.JUJU_ADMIN_PASSWORD, cacert=cacert)
            logger.info('Model connection was successful.')

            logger.info('Initializing KeyManagerFacade...')
            key_facade = client.KeyManagerFacade.from_connection(model_connection.connection)

            logger.info('Removing current ssh keys...')
            for key in current_keys:
                key = base64.b64decode(bytes(key.strip().split()[1].encode('ascii')))
                key = hashlib.md5(key).hexdigest()
                key = ':'.join(a+b for a, b in zip(key[::2], key[1::2]))
                logger.info('removing key: %s', key)
                await key_facade.DeleteKeys([key], juju_username)

            logger.info('Adding new ssh keys...')
            for key in new_keys:
                logger.info('adding key: %s', key)
                await key_facade.AddKeys([key], juju_username)

            await model_connection.disconnect()

            logger.info('Updated SSH keys for model {}!'.format(model['name']))

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
    logger = logging.getLogger('update_ssh_keys_model')
    hdlr = logging.FileHandler('{}/log/update_ssh_keys_model.log'.format(settings.SOJOBO_API_DIR))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    ws_logger.addHandler(hdlr)
    ws_logger.setLevel(logging.DEBUG)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    result = loop.run_until_complete(update_ssh_keys_model(sys.argv[1], sys.argv[2],
                                                           sys.argv[3], sys.argv[4]))
    loop.close()
