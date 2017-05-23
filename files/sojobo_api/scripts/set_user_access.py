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
def set_db_access(url, c_name, user, acl, modellist):
    try:
        logger.info('Setting up Mongo-db connection ')
        client = MongoClient(url)
        db = client.sojobo
        result = db.users.find_one({'name': unquote(user)})
        new_access = []
        if acl == 'superuser':
            logger.info('Changing to Superuser Access for controller: %s', c_name)
            for acc in result['access']:
                if list(acc.keys())[0] == c_name:
                    models = []
                    for model in modellist:
                        m_name = model['name']
                        new_model = {m_name : 'admin'}
                        models.append(new_model)
                        logger.info('Changing to Admin Access for model: %s:%s', c_name, m_name)
                    acc[c_name]['models'] = models
                    acc[c_name]['access'] = acl
                new_access.append(acc)
        else:
            logger.info('Changing to %s Access for controller: %s', acl, c_name)
            for acc in result['access']:
                if list(acc.keys())[0] == c_name:
                    acc[c_name]['access'] = acl
                new_access.append(acc)
        db.users.update_one(
            {'name' : user},
            {'$set': {'access' : new_access}}
            )
    except Exception:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)


def get_ssh_keys(usr, url):
    client = MongoClient(url)
    db = client.sojobo
    result = db.users.find_one({'name': unquote(username)})
    return result['ssh_keys']
################################################################################
# Async Functions
################################################################################
async def set_user_acc(c_name, access, user, username, password, url):
    try:
        logger.info('Setting up Controllerconnection for model: %s', c_name)
        controller = Controller()
        jujudata = JujuData()
        controller_endpoint = jujudata.controllers()[c_name]['api-endpoints'][0]
        await controller.connect(controller_endpoint, username, password)
        logger.info('Connected to controller %s ', c_name)
        try:
            await controller.revoke(user)
        except Exception:
            pass
        await controller.grant(user, acl=access)
        logger.info('Controller access set for  %s ', c_name)
        model_list = []
        ssh_keys = get_ssh_keys(user, url)
        if access == 'superuser':
            models = await controller.get_models()
            model_list = [model.serialize()['model'].serialize() for model in models.serialize()['user-models']]
            for mod in model_list:
                model_name = mod['name']
                logger.info('Setting up Modelconnection for model: %s', model_name)
                model_uuid = mod['uuid']
                model = Model()
                if not model_uuid is None:
                    await model.connect(controller_endpoint, model_uuid, username, password)
                    try:
                        await model.revoke(user)
                    except Exception:
                        pass
                    await model.grant(user, acl='admin')
                    logger.info('Admin Access granted for for %s:%s', controller_name, model_name)
                    for key in ssh_keys:
                        await model.add_ssh_key(user, key)
                    await model.disconnect()
                    logger.info('Successfully disconnected %s', model_name)
                else:
                    logger.error('Model_Uuid could not be found. Can not connect to Model : %s', model_name)
        set_db_access(url, c_name, user, access, model_list)
        await controller.disconnect()
    except Exception:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)


if __name__ == '__main__':
    username, password, api_dir, mongo_url, user, access, controller_name = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7]
    logger = logging.getLogger('set_user_access')
    hdlr = logging.FileHandler('{}/log/set_user_access.log'.format(api_dir))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    execute_task(set_user_acc, controller_name, access, user, username, password, mongo_url)
