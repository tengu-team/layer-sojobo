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
sys.path.append('/opt')
from juju import tag
from sojobo_api import settings  #pylint: disable=C0413
from sojobo_api.api import w_datastore as datastore, w_juju as juju  #pylint: disable=C0413
from juju.client import client
from juju.errors import JujuAPIError, JujuError


class JuJu_Token(object):  #pylint: disable=R0903
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.is_admin = False


async def create_model(c_name, m_key, usr, pwd, cred_name):
    try:
        token = JuJu_Token(usr, pwd)
        controller = juju.Controller_Connection(token, c_name)
        m_name = datastore.get_model(m_key)["name"]
        if not juju.get_credential(token.username, cred_name)['state'] == 'ready':
            raise Exception('The Credential {} is not ready yet.'.format(cred_name))
        credential = 't{}'.format(hashlib.md5(cred_name.encode('utf')).hexdigest())

        async with controller.connect(token) as con_juju:
            logger.info('%s -> Creating model: %s', m_name, m_name)
            model = await con_juju.add_model(
                m_name,
                cloud_name=controller.c_type,
                credential_name=credential,
                owner=tag.user(usr)
            )
            logger.info('%s -> model deployed on juju', m_name)
            datastore.set_model_access(m_key, usr, 'admin')
            datastore.set_model_state(m_key, 'ready', cred_name, model.info.uuid)
            logger.info('%s -> Adding ssh-keys to model: %s', m_name, m_name)
            for key in datastore.get_ssh_keys(usr):
                try:
                    await model.add_ssh_key(usr, key)
                except (JujuAPIError, JujuError):
                    pass
            logger.info('%s -> retrieving users: %s', m_name, datastore.get_users_controller(c_name))
            for u in datastore.get_users_controller(c_name):
                if u['access'] == 'superuser' and u['name'] != usr:
                    await model.grant(u['name'], acl='admin')
                    datastore.set_model_access(m_key, u['name'], 'admin')
                    for key in datastore.get_ssh_keys(u['name']):
                        try:
                            await model.add_ssh_key(u['name'], key['key'])
                        except (JujuAPIError, JujuError):
                            pass
            await model.disconnect()
            logger.info('%s -> succesfully deployed model', m_name)
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)
        if 'model' in locals():
            datastore.set_model_state(m_key, 'ready', cred_name, model.info.uuid)
        else:
            datastore.set_model_state(m_key, 'error: {}'.format(lines))


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger('add-model')
    ws_logger = logging.getLogger('websockets.protocol')
    hdlr = logging.FileHandler('{}/log/add_model.log'.format(sys.argv[3]))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    ws_logger.addHandler(hdlr)
    ws_logger.setLevel(logging.DEBUG)
    logger.setLevel(logging.DEBUG)
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    try:
        loop.run_until_complete(create_model(sys.argv[1], sys.argv[2], sys.argv[4],
                                             sys.argv[5], sys.argv[6]))
    finally:
        loop.close()
