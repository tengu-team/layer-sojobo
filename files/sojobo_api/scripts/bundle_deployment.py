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
import tempfile
import shutil
import os
import sys
import traceback
import ast
import logging
import yaml

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
# Helper Functions
################################################################################
def quoted_presenter(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='"')

################################################################################
# Async Functions
################################################################################
async def deploy_bundle(username, password, controller_name, model_name, bundle):
    try:
        logger.info('Authenticated and starting bundle deployment!')
        dirpath = tempfile.mkdtemp()
        os.mkdir('{}/bundle'.format(dirpath))
        bundle_dict = ast.literal_eval(bundle)
        yaml.add_representer(str, quoted_presenter)
        with open('{}/bundle/bundle.yaml'.format(dirpath), 'w+') as outfile:
            yaml.dump(bundle_dict, outfile, default_flow_style=False)
        with open('{}/bundle/README.md'.format(dirpath), 'w+') as readmefile:
            readmefile.write('##Overview')
        logger.info('Tmp file created and ready to be deployed! %s', outfile)

        logger.info('Setting up Controllerconnection for model: %s', model_name)
        controller = Controller()
        jujudata = JujuData()
        controller_endpoint = jujudata.controllers()[controller_name]['api-endpoints'][0]
        await controller.connect(controller_endpoint, username, password)
        models = await controller.get_models()
        model_list = [model.serialize()['model'].serialize() for model in models.serialize()['user-models']]
        logger.info('Connected to controller %s and models retrieved!', controller_name)

        logger.info('Setting up Modelconnection for model: %s', model_name)
        model_uuid = None
        for mod in model_list:
            if mod['name'] == model_name:
                model_uuid = mod['uuid']
        model = Model()
        if not model_uuid is None:
            await model.connect(controller_endpoint, model_uuid, username, password)
            logger.info('Deploying bundle from %s/bundle', dirpath)
            if 'series' in bundle_dict.keys():
                await model.deploy('{}/bundle'.format(dirpath), series=bundle_dict['series'])
            await model.deploy('{}/bundle'.format(dirpath))
            logger.info('Bundle successfully deployed for %s:%s', controller_name, model_name)
            await model.disconnect()
            logger.info('Successfully disconnected %s', model_name)
        else:
            logger.error('Model_Uuid could not be found. Can not connect to Model : %s', model_name)
        shutil.rmtree(dirpath)
        await controller.disconnect()
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)



if __name__ == '__main__':
    logger = logging.getLogger('bundle_deployment')
    hdlr = logging.FileHandler('{}/log/bundle_deployment.log'.format(sys.argv[3]))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    execute_task(deploy_bundle, sys.argv[1], sys.argv[2], sys.argv[4], sys.argv[5], sys.argv[6])
