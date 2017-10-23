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
from juju import tag
from juju.client import client
from sojobo_api import settings  #pylint: disable=C0413
from sojobo_api.api import w_datastore as ds, w_juju as juju  #pylint: disable=C0413

class JuJu_Token(object):  #pylint: disable=R0903
    def __init__(self):
        self.username = settings.JUJU_ADMIN_USER
        self.password = settings.JUJU_ADMIN_PASSWORD
        self.is_admin = False

async def remove_credential(username, cred_name):
    try:
        token = JuJu_Token()
        cred = juju.get_credential(username, cred_name)
        credential_name = 't{}'.format(hashlib.md5(cred_name.encode('utf')).hexdigest())
        logger.info('Succesfully retrieved credential, removing credential now')
        c_type = cred['type']
        controllers = ds.get_cloud_controllers(c_type)
        for con in controllers:
            controller = juju.Controller_Connection(token, con)
            if controller.c_type == c_type:
                async with controller.connect(token) as con_juju:
                    cloud_facade = client.CloudFacade.from_connection(con_juju.connection)
                    cloud_cred = client.Entity(tag.credential(c_type, username, credential_name))
                    await cloud_facade.RevokeCredentials([cloud_cred])
        ds.remove_credential(username, cred_name)
        logger.info('Succesfully removed credential')
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)


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
