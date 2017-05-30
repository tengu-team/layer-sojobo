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
# pylint: disable=c0111,c0301,c0325,c0103,r0204,r0913,r0902,e0401,C0302, R0914
import asyncio
from urllib.parse import unquote
import sys
import traceback
import logging

from pymongo import MongoClient
from juju.client.connection import JujuData
from juju.model import Model
from juju.controller import Controller

################################################################################
# Asyncio Wrapper
################################################################################
def execute_task(command, *args):
    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    result = loop.run_until_complete(command(*args))
    return result

################################################################################
# Mongo Functions
################################################################################
def get_user_by_id(user_id, mongo):
    result = mongo.users.find_one({'_id': user_id})
    return result

def get_controller(c_name, mongo):
    result = mongo.controllers.find_one({'name': unquote(c_name)})
    return result

def get_controller_users(controller, mongo):
    cont = get_controller(controller, mongo)
    result = []
    for user_id in cont['users']:
        user = get_user_by_id(user_id, mongo)
        result.append(user)
    return result


def get_ssh_keys(usr, mongo):
    result = mongo.users.find_one({'name': unquote(username)})
    return result['ssh_keys']


def get_controller_access(c_name, user, mongo):
    result = mongo.users.find_one({'name': unquote(user)})
    for acc in result['access']:
        if list(acc.keys())[0] == c_name:
            return acc[c_name]['access']

def get_superusers(c_name, mongo):
    result = []
    users = get_controller_users(c_name, mongo)
    for user in users:
        if get_controller_access(c_name, user['name'], mongo) == 'superuser':
            result.append(user['name'])
    return result

def set_model_access(c_name, m_name, usr, mongo, access):
    result = mongo.users.find_one({'name': unquote(usr)})
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
    mongo.users.update_one(
        {'name' : username},
        {'$set': {'access' : new_access}}
        )

def set_model_state(c_name, m_name, state, mongo):
    con = get_controller(c_name, mongo)
    new_models = []
    for mod in con['models']:
        logger.info('mod: %s --- %s --- %s', mod, list(mod.keys())[0], state)
        if list(mod.keys())[0] == m_name:
            new_mod = {}
            new_mod[m_name] = state
            mod = new_mod
        new_models.append(mod)
    mongo.controllers.update_one(
        {'name' : c_name},
        {'$set': {'models' : new_models}}
        )
################################################################################
# Async Functions
################################################################################
async def create_model(c_name, m_name, usr, pwd, url):
    try:
        logger.info('Setting up Controllerconnection for %s', c_name)
        controller = Controller()
        jujudata = JujuData()
        controller_endpoint = jujudata.controllers()[c_name]['api-endpoints'][0]
        await controller.connect(controller_endpoint, usr, pwd)
        await controller.add_model(m_name)

        client = MongoClient(url)
        db = client.sojobo
        s_users = get_superusers(c_name, db)
        userkeys = get_ssh_keys(usr, db)
        adminkeys = get_ssh_keys('admin', db)

        logger.info('Setting up Modelconnection for model: %s', m_name)
        models = await controller.get_models()
        list_models = [model.serialize()['model'].serialize() for model in models.serialize()['user-models']]
        model_uuid = None
        for mod in list_models:
            if mod['name'] == m_name:
                model_uuid = mod['uuid']
        model = Model()
        if not model_uuid is None:
            await model.connect(controller_endpoint, model_uuid, username, password)
            for key in userkeys:
                model.add_ssh_key(usr, key)
            for key in adminkeys:
                model.add_ssh_key('admin', key)
            for user in s_users:
                if user != 'admin':
                    await model.grant(user, acl='admin')
                    sshkey = get_ssh_keys(user, db)
                    for key in sshkey:
                        model.add_ssh_key(user, key)
                set_model_access(c_name, m_name, user, db, 'admin')
                logger.info('Admin Access granted for user %s on model %s', user, m_name)
        set_model_state(c_name, m_name, 'ready', db)
        set_model_access(c_name, m_name, usr, db, 'admin')
        await model.disconnect()
        await controller.disconnect()
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)
        set_model_state(c_name, m_name, 'ERROR: {}'.format(e), db)


if __name__ == '__main__':
    username, password, api_dir, mongo_url, controller_name, model_name = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6]
    logger = logging.getLogger('add-model')
    hdlr = logging.FileHandler('{}/log/add_model.log'.format(api_dir))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    execute_task(create_model, controller_name, model_name, username, password, mongo_url)
