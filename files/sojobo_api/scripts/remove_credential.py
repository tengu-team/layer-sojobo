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
import hashlib
sys.path.append('/opt')
from juju import tag, errors
from juju.client import client
from juju.controller import Controller
from sojobo_api import settings  #pylint: disable=C0413
from sojobo_api.api.storage import w_datastore as datastore
from sojobo_api.api import w_juju as juju  #pylint: disable=C0413


async def remove_credential(username, cred_name):
    try:
        # TODO: If time, make it so that less datastore calls are made.
        logger.info('Retrieving credential from database...')
        cred = juju.get_credential(username, cred_name)
        credential_name = 't{}'.format(hashlib.md5(cred_name.encode('utf')).hexdigest())

        comp = datastore.get_company_user(username)
        if not comp:
            company = None
        else:
            company = comp['company']

        logger.info('Succesfully retrieved credential from database...')

        c_type = cred['type']
        controllers = datastore.get_cloud_controllers(username, c_type, company=company)

        for con in controllers:
            if con["type"] == c_type:
                logger.info('Setting up Controller connection for %s.', con["name"])
                controller_connection = Controller()
                await controller_connection.connect(endpoint=con["endpoints"][0],
                                                    username=settings.JUJU_ADMIN_USER,
                                                    password=settings.JUJU_ADMIN_PASSWORD,
                                                    cacert=con["ca_cert"])
                logger.info('Controller connection as admin was successful.')

                logger.info('Removing credential from controller %s.', con["name"])
                cloud_facade = client.CloudFacade.from_connection(controller_connection.connection)
                cloud_cred = client.Entity(tag.credential(c_type, username, credential_name))
                await cloud_facade.RevokeCredentials([cloud_cred])
                logger.info('Credential was successfully removed from controller %s.', con["name"])

        logger.info('Removing credential from database...')
        datastore.remove_credential(username, cred_name)
        logger.info('Succesfully removed credential!')
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)
    finally:
        if 'controller_connection' in locals():
            await juju.disconnect(controller_connection)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    ws_logger = logging.getLogger('websockets.protocol')
    logger = logging.getLogger('remove_credential')
    hdlr = logging.FileHandler('{}/log/remove_credential.log'.format(sys.argv[3]))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    ws_logger.addHandler(hdlr)
    ws_logger.setLevel(logging.DEBUG)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    loop.run_until_complete(remove_credential(sys.argv[1], sys.argv[2]))
    loop.close()
