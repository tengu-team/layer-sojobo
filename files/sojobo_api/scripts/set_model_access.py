#!/usr/bin/env python3
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
import ast
import traceback
import logging
sys.path.append('/opt')
from sojobo_api.api import w_datastore as datastore, w_juju as juju  #pylint: disable=C0413
from juju.errors import JujuAPIError, JujuError

class JuJu_Token(object):  #pylint: disable=R0903
    def __init__(self):
        self.username = None
        self.password = None

async def set_model_acc(username, password, user, access, controller):
    try:
        logger.info('Starting process to set model access')
        token = JuJu_Token
        token.username = username
        token.password = password
        access_list = ast.literal_eval(access)
        ssh_keys = datastore.get_ssh_keys(user)
        for mod in access_list:
            logger.info('setting Model Access for %s on %s!', user, mod['name'])
            model = juju.Model_Connection(token, controller, mod['name'])
            async with model.connect(token) as mod_con:
                current_access = datastore.get_model_access(controller, mod['name'], user)
                logger.info('Current Access level: %s', current_access)
                if current_access:
                    await mod_con.revoke(user)
                await mod_con.grant(user, acl=mod['access'])
                if mod['access'] in ['admin', 'write']:
                    for key in ssh_keys:
                        try:
                            mod_con.add_ssh_key(user, key)
                        except (JujuAPIError, JujuError):
                            pass
            datastore.set_model_access(controller, mod['name'], user, mod['access'])
            logger.info('Model Access set for %s on %s!', user, mod['name'])
    except Exception:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    ws_logger = logging.getLogger('websockets.protocol')
    logger = logging.getLogger('set_model_access')
    hdlr = logging.FileHandler('{}/log/set_model_access.log'.format(sys.argv[3]))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    ws_logger.addHandler(hdlr)
    ws_logger.setLevel(logging.DEBUG)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    result = loop.run_until_complete(set_model_acc(sys.argv[1], sys.argv[2],
                                                   sys.argv[4], sys.argv[5], sys.argv[6]))
    loop.close()
