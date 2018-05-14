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
import tempfile
import shutil
import os
import sys
import traceback
import json
import logging
import yaml
from juju.model import Model, BundleHandler
sys.path.append('/opt')
from sojobo_api import settings
from sojobo_api.api.storage import w_datastore as datastore
from sojobo_api.api import w_juju as juju
################################################################################
# Helper Functions
################################################################################
def quoted_presenter(dumper, data):
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='"')
################################################################################
# Async Functions
################################################################################
async def deploy_bundle(username, password, c_name, m_name, bundle):
    try:
        logger.info('Authenticated and starting bundle deployment!')
        m_key = datastore.get_model_key(c_name, m_name)
        auth_data = datastore.get_model_connection_info(username, c_name, m_key)
        dirpath = tempfile.mkdtemp()

        logger.info('Create the bundle in tmp dir')
        os.mkdir('{}/bundle'.format(dirpath))
        bundle_dict = json.loads(bundle)
        yaml.add_representer(str, quoted_presenter)
        with open('{}/bundle/bundle.yaml'.format(dirpath), 'w+') as outfile:
            yaml.dump(bundle_dict, outfile, default_flow_style=False)
        with open('{}/bundle/README.md'.format(dirpath), 'w+') as readmefile:
            readmefile.write('##Overview')
        logger.info('Tmp file created and ready to be deployed! %s', outfile)
        logger.info('Setting up Modelconnection for model: %s', m_name)
        model = Model()
        juju_username = auth_data["user"]["juju_username"]
        await model.connect(auth_data['controller']['endpoints'][0], auth_data['model']['uuid'], juju_username, password, auth_data['controller']['ca_cert'])
        logger.info('Deploying bundle from %s/bundle', dirpath)

        handler = BundleHandler(model)
        await handler.fetch_plan('{}/bundle'.format(dirpath))
        await handler.execute_plan()
        extant_apps = {app for app in model.applications}
        pending_apps = set(handler.applications) - extant_apps
        if pending_apps:
            # new apps will usually be in the model by now, but if some
            # haven't made it yet we'll need to wait on them to be added
            await asyncio.gather(*[
                asyncio.ensure_future(
                    model._wait_for_new('application', app_name),
                    loop=model.loop)
                for app_name in pending_apps
            ], loop=model.loop)
        logger.info('Bundle successfully deployed for %s:%s', c_name, m_name)


        if juju.monitoring_enabled(auth_data["model"]):
            logger.info('Updating monitoring relations for %s:%s', c_name, m_name)
            applications_info = juju.get_applications_info(model)
            endpoint = auth_data["controller"]["endpoints"][0]
            cacert = auth_data["controller"]["ca_cert"]
            uuid = auth_data["model"]["uuid"]
            juju.update_monitoring_relations(c_name, endpoint, cacert, m_name,
                                             uuid, juju_username, password,
                                             applications_info)


        await model.disconnect()
        logger.info('Successfully disconnected %s', m_name)
        shutil.rmtree(dirpath)
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)
    finally:
        if 'model' in locals():
            await juju.disconnect(model)

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    ws_logger = logging.getLogger('websockets.protocol')
    logger = logging.getLogger('bundle_deployment')
    hdlr = logging.FileHandler('{}/log/bundle_deployment.log'.format(settings.SOJOBO_API_DIR))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    ws_logger.addHandler(hdlr)
    ws_logger.setLevel(logging.DEBUG)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    loop.run_until_complete(deploy_bundle(sys.argv[1], sys.argv[2], sys.argv[3],
                                          sys.argv[4], sys.argv[5]))
    loop.close()
