
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
from sojobo_api.api.storage import w_datastore as datastore
from sojobo_api.api import w_juju as juju  #pylint: disable=C0413


async def update_ssh_keys_all_models(ssh_keys, username):
    """Updates the ssh keys of a user on every model where the user has admin
    or write access to."""
    try:
        user_info = datastore.get_user_info(username)
        juju_username = user_info["juju_username"]
        current_keys = user_info["ssh_keys"]
        json_acceptable_string = ssh_keys.replace("'", "\"")
        new_keys = json.loads(json_acceptable_string)


        for controller in user_info["controllers"]:
            endpoint = controller["endpoints"][0]
            cacert = controller["ca_cert"]

            for model in controller['models']:
                mod_access = model["access"]
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
    logger = logging.getLogger('update_ssh_keys_all_models')
    hdlr = logging.FileHandler('{}/log/update_ssh_keys_all_models.log'.format(settings.SOJOBO_API_DIR))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    ws_logger.addHandler(hdlr)
    ws_logger.setLevel(logging.DEBUG)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    result = loop.run_until_complete(update_ssh_keys_all_models(sys.argv[1], sys.argv[2]))
    loop.close()
