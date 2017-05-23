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
def get_controller_access(controller_name, username, mongo):
    result = mongo.users.find_one({'name': unquote(username)})
    for acc in result['access']:
        if list(acc.keys())[0] == controller_name:
            return acc[controller_name]['access']


def get_model_access(controller, model, user, mongo):
    result = mongo.users.find_one({'name': unquote(user)})
    for acc in result['access']:
        if list(acc.keys())[0] == controller:
            models = acc[controller]['models']
            for mod in models:
                if list(mod.keys())[0] == model:
                    return mod[model]
    return None


def get_ssh_keys(usr, mongo):
    result = mongo.users.find_one({'name': unquote(usr)})
    return result['ssh_keys']


def remove_ssh_key(user, ssh_key, mongo):
    mongo.users.update_one(
        {'name' : user},
        {'$pull': {'ssh_keys' : ssh_key}}
        )
################################################################################
# Async Functions
################################################################################
async def remove_ssh_keys(c_name, usrname, pwd, ssh_key, url, user):
    try:
        client = MongoClient(url)
        db = client.sojobo

        if ssh_key in get_ssh_keys(user, db):
            remove_ssh_key(user, ssh_key, db)

        logger.info('Setting up Controllerconnection for %s', c_name)
        controller = Controller()
        jujudata = JujuData()
        controller_endpoint = jujudata.controllers()[c_name]['api-endpoints'][0]
        await controller.connect(controller_endpoint, usrname, pwd)

        acl_lvl = get_controller_access(c_name, user, db)
        models = await controller.get_models()
        model_list = [model.serialize()['model'].serialize() for model in models.serialize()['user-models']]
        if acl_lvl == 'superuser':
            for mod in model_list:
                model_name = mod['name']
                logger.info('Setting up Modelconnection for model: %s', model_name)
                model_uuid = mod['uuid']
                model = Model()
                if not model_uuid is None:
                    await model.connect(controller_endpoint, model_uuid, username, password)
                    await model.remove_ssh_key(user, ssh_key)
                    await model.disconnect()
        else:
            for mod in model_list:
                model_name = mod['name']
                mod_lvl = get_model_access(c_name, model_name, user, db)
                if mod_lvl == 'admin' or mod_lvl == 'write':
                    logger.info('Setting up Modelconnection for model: %s', model_name)
                    model_uuid = mod['uuid']
                    model = Model()
                    if not model_uuid is None:
                        await model.connect(controller_endpoint, model_uuid, username, password)
                        await model.remove_ssh_key(user, ssh_key)
                        await model.disconnect()
        await controller.disconnect()
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)



if __name__ == '__main__':
    username, password, api_dir, controller_name, ssh_key, mongo_url, user= sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7]
    logger = logging.getLogger('remove_ssh_keys')
    hdlr = logging.FileHandler('{}/log/remove_ssh_keys.log'.format(api_dir))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    execute_task(remove_ssh_keys, controller_name, username, password, ssh_key, mongo_url, user)
