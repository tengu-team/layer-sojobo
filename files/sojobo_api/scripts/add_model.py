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
import redis
from juju import tag
from juju.controller import Controller
from juju.client import client
################################################################################
# Datastore Functions
################################################################################
def set_model_access(c_name, m_name, user, connection, access):
    user_data = connection.get(user)
    result = json.loads(user_data)
    for con in result['controllers']:
        if con['name'] == c_name:
            for mod in con['models']:
                if mod['name'] == m_name:
                    mod['access'] = access
                    break
            break
    connection.set(user, json.dumps(result))


def set_model_state(c_name, m_name, state, connection, uuid=None):
    con = json.loads(connection.get(c_name))
    for mod in con['models']:
        if mod['name'] == m_name:
            mod['status'] = state
            if uuid:
                mod['uuid'] = uuid
            break
    connection.set(c_name, json.dumps(con))
################################################################################
# Async Functions
################################################################################
async def create_model(c_name, m_name, usr, pwd, url, port, cred_name):
    try:
        logger.info('Setting up Controllerconnection for %s', c_name)
        users = redis.StrictRedis(host=url, port=port, charset="utf-8", decode_responses=True, db=11)
        controllers = redis.StrictRedis(host=url, port=port, charset="utf-8", decode_responses=True, db=10)
        controller = Controller()
        await controller.connect(json.loads(controllers.get(c_name))['endpoints'][0], usr, pwd)
        c_type = json.loads(controllers.get(c_name))['type']
        logger.info('Adding credentials')
        cloud_facade = client.CloudFacade.from_connection(controller.connection)
        for cred in json.loads(users.get(usr))['credentials']:
            if cred['name'] == cred_name:
                credential = cred
                cloud_cred = client.UpdateCloudCredential(
                    client.CloudCredential(cred['key'], cred['type']),
                    tag.credential(c_type, usr, cred['name'])
                )
                await cloud_facade.UpdateCredentials([cloud_cred])
        logger.info('Creating model: %s', m_name)
        model = await controller.add_model(
            m_name,
            cloud_name=c_type,
            credential_name=credential['name'],
            owner=tag.user(usr)
        )
        logger.info('Adding ssh-keys to model and setting up grants: %s', m_name)
        set_model_access(c_name, m_name, usr, users, 'admin')
        for key in json.loads(users.get(usr))['ssh-keys']:
            await model.add_ssh_key(usr, key)
        for u in json.loads(controllers.get(c_name))['users']:
            if u['access'] == 'superuser':
                await model.grant(u['name'], acl='admin')
                set_model_access(c_name, m_name, u['name'], users, 'admin')
                for key in json.loads(users.get(u['name']))['ssh-keys']:
                    await model.add_ssh_key(u['name'], key)
        set_model_state(c_name, m_name, 'ready', controllers, model.info.uuid)
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)
        if 'model' in locals():
            set_model_state(c_name, m_name, 'ready', controllers,model.serialize()['model'].serialize()['uuid'] )
        else:
            set_model_state(c_name, m_name, 'ERROR: {}'.format(e), controllers)
    finally:
        if 'model' in locals():
            await model.disconnect()
        await controller.disconnect()


if __name__ == '__main__':
    logger = logging.getLogger('add-model')
    hdlr = logging.FileHandler('{}/log/add_model.log'.format(sys.argv[3]))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    loop.run_until_complete(create_model(sys.argv[6], sys.argv[7], sys.argv[1],
                                         sys.argv[2], sys.argv[4], sys.argv[5], sys.argv[8]))
    loop.close()
