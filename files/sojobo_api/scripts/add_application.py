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
import yaml
import json
from juju.client import client
from juju.model import Model
sys.path.append('/opt')
from sojobo_api import settings
from sojobo_api.api import w_datastore as datastore, w_juju as juju


async def add_application(c_name, m_key, username, password, units, machine, config, application, series):
    try:
        auth_data = datastore.get_model_connection_info(username, c_name, m_key)
        model_connection = Model()
        logger.info('Setting up Model connection for %s:%s', c_name, auth_data['model']['name'])
        await model_connection.connect(auth_data['controller']['endpoints'][0],
                                       auth_data['model']['uuid'],
                                       auth_data['user']['juju_username'],
                                       password,
                                       auth_data['controller']['ca_cert'])
        logger.info('Model connection was successful.')

        logger.info('Creating model entity...')
        entity = await model_connection.charmstore.entity(application, channel=None)
        entity_id = entity['Id']
        logger.info('Created model entity.')

        client_facade = client.ClientFacade.from_connection(model_connection.connection)
        app_facade = client.ApplicationFacade.from_connection(model_connection.connection)

        # If the application is a subordinate it does not need any units.
        if entity['Meta']['charm-metadata']['Subordinate']:
            units = 0

        if series == '':
            series = model_connection._get_series(application, entity)
        await client_facade.AddCharm(None, entity_id)

        # When someone tries to deploy a non-recommended app then they need to
        # specify the whole name of the charm (including creator). F.e.
        # 'cs:~chris.macnaughton/influxdb' in contrast to the recommended charm
        # 'influxdb'. client.ApplicationDeploy().application only needs 'influxdb'
        # and no other details.
        if "/" in application:
            application = application.split("/")[1]

        conf_dict = json.loads(config)
        if conf_dict:
            conf = {k: str(v) for k, v in conf_dict.items()}
        else:
            conf = {}
        config = yaml.dump({application: conf}, default_flow_style=False)

        if machine:
            placement = [client.Placement(
                scope="#",
                directive=machine
            )]
        else:
            placement = None

        app = client.ApplicationDeploy(
            charm_url=entity_id,
            application=application,
            series=series,
            channel=None,
            config_yaml=config,
            constraints=None,
            endpoint_bindings=None,
            num_units=int(units),
            resources=None,
            storage=None,
            placement=placement
        )

        await app_facade.Deploy([app])

        # If monitoring is enabled for the workspace then we need to add a
        # relation between the application and the tengu monitoring telegraf.
        if juju.monitoring_enabled(auth_data["model"]):
            m_name = auth_data["model"]["name"]
            logger.info('Updating monitoring relations for %s:%s', c_name, m_name)
            applications_info = juju.get_applications_info(model_connection)
            endpoint = auth_data["controller"]["endpoints"][0]
            cacert = auth_data["controller"]["ca_cert"]
            uuid = auth_data["model"]["uuid"]
            juju_username = auth_data["user"]["juju_username"]
            juju.update_monitoring_relations(c_name, endpoint, cacert, m_name,
                                             uuid, juju_username, password,
                                             applications_info)
            juju.add_monitoring_to_app(c_name, endpoint, cacert, m_name,
                                uuid, juju_username, password, application)

        await model_connection.disconnect()
        logger.info('Application %s succesfully added!', application)
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)
    finally:
        if 'model_connection' in locals():
            await juju.disconnect(model_connection)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    ws_logger = logging.getLogger('websockets.protocol')
    logger = logging.getLogger('add_application')
    hdlr = logging.FileHandler('{}/log/add_application.log'.format(settings.SOJOBO_API_DIR))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    ws_logger.addHandler(hdlr)
    ws_logger.setLevel(logging.DEBUG)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    loop.run_until_complete(add_application(sys.argv[1], sys.argv[2], sys.argv[3],
                                            sys.argv[4], sys.argv[5], sys.argv[6],
                                            sys.argv[7], sys.argv[8], sys.argv[9]))
    loop.close()
