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
from juju.client.connection import JujuData
from juju import tag
from juju.controller import Controller
from juju.client import client
################################################################################
# Asyncio Wrapper
################################################################################
def execute_task(command, *args):
    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    result = loop.run_until_complete(command(*args))
    loop.close()
    return result
################################################################################
# Datastore Functions
################################################################################
def get_controller(c_name, connection):
    result = connection.get(c_name)
    return json.loads(result)


def get_controller_users(controller, user_db, cont_db):
    cont = get_controller(controller, cont_db)
    result = []
    for user in cont['users']:
        user_obj = user_db.get(user)
        json_user = json.loads(user_obj)
        result.append(json_user)
    return result


def get_ssh_keys(user, connection):
    data = connection.get(user)
    return [k for k in json.loads(data)['ssh_keys'] if k is not None]


def get_controller_access(c_name, user, connection):
    json_data = connection.get(user)
    data = json.loads(json_data)
    for acc in data['access']:
        if list(acc.keys())[0] == c_name:
            return acc[c_name]['access']


def get_superusers(c_name, user_db, cont_db):
    result = []
    users = get_controller_users(c_name, user_db, cont_db)
    for user in users:
        if get_controller_access(c_name, user['name'], user_db) == 'superuser':
            result.append(user['name'])
    return result


def get_credentials(user, connection, cred_name):
    user_data = connection.get(user)
    data = json.loads(user_data)
    for creds in data['credentials']:
        if creds['name'] == cred_name:
            return creds


def set_model_access(c_name, m_name, user, connection, access):
    user_data = connection.get(user)
    result = json.loads(user_data)
    new_access = []
    for acc in result['access']:
        if list(acc.keys())[0] == c_name:
            models = acc[c_name]['models']
            for modelname in models:
                if list(modelname.keys())[0] == m_name:
                    models.remove(modelname)
            new_model = {m_name: access}
            models.append(new_model)
            acc[c_name]['models'] = models
        new_access.append(acc)
    result['access'] = new_access
    json_result = json.dumps(result)
    connection.set(user, json_result)


def set_model_state(c_name, m_name, state, connection):
    con = get_controller(c_name, connection)
    new_models = []
    for mod in con['models']:
        if list(mod.keys())[0] == m_name:
            new_mod = {}
            new_mod[m_name] = state
            mod = new_mod
        new_models.append(mod)
    con['models'] = new_models
    j_con = json.dumps(con)
    connection.set(c_name, j_con)
################################################################################
# Async Functions
################################################################################
async def create_model(c_name, m_name, usr, pwd, url, port, cred_name):
    try:
        logger.info('Setting up Controllerconnection for %s', c_name)
        controller = Controller()
        jujudata = JujuData()
        controller_endpoint = jujudata.controllers()[c_name]['api-endpoints'][0]
        user_db = redis.StrictRedis(host=url, port=port, charset="utf-8", decode_responses=True, db=11)
        cont_db = redis.StrictRedis(host=url, port=port, charset="utf-8", decode_responses=True, db=10)
        s_users = get_superusers(c_name, user_db, cont_db)
        userkeys = get_ssh_keys(usr, user_db)
        adminkeys = get_ssh_keys('admin', user_db)
        await controller.connect(controller_endpoint, usr, pwd)
        logger.info('Setting up Modelconnection for model: %s', m_name)
        c_type = get_controller(c_name, cont_db)['type']
        cloud_facade = client.CloudFacade.from_connection(controller.connection)
        credentialfile = get_credentials(usr, user_db, cred_name)
        cred = client.CloudCredential(credentialfile['key'], credentialfile['type'])
        update_cloudcred = client.UpdateCloudCredential(cred, tag.credential(c_type, usr, credentialfile['name']))
        await cloud_facade.UpdateCredentials([update_cloudcred])
        model = await controller.add_model(m_name, cloud_name=c_type, credential_name=credentialfile['name'], owner=tag.user(usr))
        for key in userkeys:
            await model.add_ssh_key(usr, key)
        for key in adminkeys:
            await model.add_ssh_key('admin', key)
        for user in s_users:
            if user != 'admin':
                await model.grant(user, acl='admin')
                sshkey = get_ssh_keys(user, user_db)
                for key in sshkey:
                    await model.add_ssh_key(user, key)
            set_model_access(c_name, m_name, user, user_db, 'admin')
            logger.info('Admin Access granted for user %s on model %s', user, m_name)
        set_model_state(c_name, m_name, 'ready', cont_db)
        set_model_access(c_name, m_name, usr, user_db, 'admin')
    except Exception as e:
        models = await controller.get_models()
        list_models = [model.serialize()['model'].serialize() for model in models.serialize()['user-models']]
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)
        if m_name in list_models:
            set_model_state(c_name, m_name, 'ready', cont_db)
        else:
            set_model_state(c_name, m_name, 'ERROR: {}'.format(e), cont_db)
    finally:
        if 'model' in locals():
            await model.disconnect()
        await controller.disconnect()


if __name__ == '__main__':
    username, password, api_dir, url, port, controller_name, model_name, cred_name = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7], sys.argv[8]
    logger = logging.getLogger('add-model')
    hdlr = logging.FileHandler('{}/log/add_model.log'.format(api_dir))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    execute_task(create_model, controller_name, model_name, username, password, url, port, cred_name)
