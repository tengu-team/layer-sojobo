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
import logging
import os
import hashlib
from pathlib import Path
from subprocess import check_output
import traceback
import sys
import yaml
from juju import tag
from juju.client import client
sys.path.append('/opt')
from sojobo_api import settings  #pylint: disable=C0413
from sojobo_api.api import w_datastore as datastore, w_juju as juju  #pylint: disable=C0413


class JuJu_Token(object):  #pylint: disable=R0903
    def __init__(self):
        self.username = settings.JUJU_ADMIN_USER
        self.password = settings.JUJU_ADMIN_PASSWORD
        self.is_admin = True


async def create_controller(c_type, name, region, cred_name):
    try:
        logger.info('Adding controller to database')
        token = JuJu_Token()
        datastore.create_controller(name, c_type, region, cred_name)
        datastore.add_user_to_controller(name, 'admin', 'superuser')

        logger.info('Bootstrapping controller')
        credential = juju.get_credential(token.username, cred_name)
        logger.info('credential found %s:', credential['credential'])
        juju.get_controller_types()[c_type].create_controller(name, region, credential['credential'], 't{}'.format(hashlib.md5(cred_name.encode('utf')).hexdigest()))
        pswd = token.password

        logger.info('Setting admin password')
        check_output(['juju', 'change-user-password', 'admin', '-c', name],
                     input=bytes('{}\n{}\n'.format(pswd, pswd), 'utf-8'))

        logger.info('Updating controller in database')
        with open(os.path.join(str(Path.home()), '.local', 'share', 'juju', 'controllers.yaml'), 'r') as data:
            con_data = yaml.load(data)
        datastore.set_controller_state(
            name,
            'ready',
            con_data['controllers'][name]['api-endpoints'],
            con_data['controllers'][name]['uuid'],
            con_data['controllers'][name]['ca-cert'])

        logger.info('Connecting to controller')
        controller = juju.Controller_Connection(token, name)

        logger.info('Adding existing credentials and models to database')
        credentials = datastore.get_credentials(token.username)
        async with controller.connect(token) as juju_con:
            for cred in credentials:
                if cred['name'] != cred_name:
                    credential_name = 't{}'.format(hashlib.md5(cred_name.encode('utf')).hexdigest())
                    cloud_facade = client.CloudFacade.from_connection(juju_con.connection)
                    credential = juju.generate_cred_file(c_type, credential_name, cred['credential'])
                    cloud_cred = client.UpdateCloudCredential(
                        client.CloudCredential(credential['key'], credential['type']),
                        tag.credential(c_type, token.username, credential_name)
                    )
                    await cloud_facade.UpdateCredentials([cloud_cred])
            models = await juju_con.get_models()
            for model in models.serialize()['user-models']:
                model = model.serialize()['model'].serialize()
                datastore.add_model_to_controller(name, model['name'])
                datastore.set_model_state(name, model['name'], 'ready', model['uuid'])
                datastore.set_model_access(name, model['name'], token.username, 'admin')
        logger.info('Controller succesfully created!')
    except Exception:  #pylint: disable=W0703
        datastore.destroy_controller(name)
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)
        datastore.set_controller_state(name, 'error')


if __name__ == '__main__':
    logger = logging.getLogger('add-controller')
    hdlr = logging.FileHandler('{}/log/add_controller.log'.format(settings.SOJOBO_API_DIR))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    loop.run_until_complete(create_controller(sys.argv[1], sys.argv[2],
                                              sys.argv[3], sys.argv[4]))
    loop.close()
