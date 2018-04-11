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
from juju import tag, utils, errors
from juju.client import client
from juju.model import Model
from juju.controller import Controller
from juju.errors import JujuAPIError, JujuError
sys.path.append('/opt')
from sojobo_api import settings  #pylint: disable=C0413
from sojobo_api.api import w_datastore as datastore, w_juju as juju  #pylint: disable=C0413


async def create_model(c_name, m_key, m_name, usr, pwd, cred_name):
    try:
        # Get required information from database
        auth_data = datastore.get_controller_connection_info(usr, c_name)
        credential_name = 't{}'.format(hashlib.md5(cred_name.encode('utf')).hexdigest())

        # Controller_Connection
        logger.info('Setting up Controllerconnection for %s', c_name)
        controller_connection = Controller()
        await controller_connection.connect(auth_data['controller']['endpoints'][0],
                                            auth_data['user']['juju_username'], pwd)
        owner = tag.user(auth_data['user']['juju_username'])

        # Generate Tag for Credential
        credential = tag.credential(
            auth_data['controller']['type'],
            tag.untag('user-', owner),
            credential_name
        )

        # model_info = await controller_connection.add_model(m_name)
        cloud = tag.cloud(auth_data['controller']['type'])
        region = auth_data['controller']['region']
        # model_info = await controller_connection.add_model(m_name)
        config = {}
        #config['authorized-keys'] = await utils.read_ssh_key(loop=controller_connection.loop)
        logger.info('========================================================')
        logger.info('config = %s', config)
        logger.info('========================================================')
        logger.info('credential = %s', credential)
        logger.info('========================================================')
        logger.info('owner = %s', owner)
        logger.info('========================================================')
        logger.info('cloud = %s', cloud)
        logger.info('========================================================')
        logger.info('region = %s', region)
        logger.info('========================================================')
        logger.info('m_name = %s', m_name)

        # Create A Model
        model_facade = client.ModelManagerFacade.from_connection(controller_connection.connection)
        model_info = await model_facade.CreateModel(cloud, config, credential,
                                                    m_name, owner,
                                                    region)
        logger.info('%s -> Connected to model', m_name)
        # Connect to created Model

        model = Model()
        await model.connect(
            controller_connection.connection.endpoint,
            model_info.uuid,
            controller_connection.connection.username,
            controller_connection.connection.password,
            controller_connection.connection.cacert,
            controller_connection.connection.macaroons
        )
        logger.info('%s -> model deployed on juju', m_name)

        # Set Datastore information for creator
        datastore.set_model_access(m_key, usr, 'admin')
        datastore.set_model_state(m_key, 'ready', cred_name, model.info.uuid)

        # Generate Facades for new model
        key_facade = client.KeyManagerFacade.from_connection(model.connection)

        # Add SSH-keys for owner
        # logger.info('%s -> Adding ssh-keys to model: %s', m_name, m_name)
        # for key in auth_data['user']['ssh-keys']:
        #     try:
        #         key_facade.AddKeys([key], auth_data['user'])
        #     except (JujuAPIError, JujuError):
        #         pass

        # Give Superusers right Access and add their SSH-Keys to model
        con_users = datastore.get_users_controller(c_name)
        logger.info('%s -> retrieving users: %s', m_name, con_users)
        for u in con_users:
            if u['access'] == 'superuser' and u['name'] != usr:
                user = tag.user(u['juju_username'])
                uuid_tag = tag.model(model_info.uuid)
                changes = client.ModifyModelAccess('admin', 'grant', uuid_tag, user)
                await model_facade.ModifyModelAccess([changes])
                datastore.set_model_access(m_key, u['name'], 'admin')
                for key in datastore.get_ssh_keys(u['name']):
                    try:
                        key_facade.AddKeys([key], u['name'])
                    except (JujuAPIError, JujuError):
                        pass
        juju.log_event('model.create',
                       {'uuid': model_info.uuid,
                        'name': m_name})
        logger.info('%s -> succesfully deployed model', m_name)
        await model.disconnect()
        await controller_connection.disconnect()
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)
        datastore.set_model_state(m_key, 'error: {}'.format(lines))
    finally:
        if 'controller_connection' in locals():
            await juju.disconnect(controller_connection)
            if 'model' in locals():
                await juju.disconnect(model)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger('add_model')
    ws_logger = logging.getLogger('websockets.protocol')
    hdlr = logging.FileHandler('{}/log/add_model.log'.format(settings.SOJOBO_API_DIR))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    ws_logger.addHandler(hdlr)
    ws_logger.setLevel(logging.DEBUG)
    logger.setLevel(logging.DEBUG)
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    loop.run_until_complete(create_model(sys.argv[1], sys.argv[2], sys.argv[3],
                                         sys.argv[4], sys.argv[5], sys.argv[6]))
    loop.close()
