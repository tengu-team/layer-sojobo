
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
import ast
import sys
import traceback
import logging
sys.path.append('/opt')
from sojobo_api import settings  #pylint: disable=C0413
from sojobo_api.api import w_datastore as datastore, w_juju as juju  #pylint: disable=C0413

class JuJu_Token(object):  #pylint: disable=R0903
    def __init__(self):
        self.username = settings.JUJU_ADMIN_USER
        self.password = settings.JUJU_ADMIN_PASSWORD
        self.is_admin = True

async def remove_ssh_key(ssh_keys, username):
    try:
        current_keys = datastore.get_ssh_keys(username)
        new_keys = ast.literal_eval(ssh_keys)
        user = datastore.get_user(username)
        token = JuJu_Token()
        for con in user['controllers']:
            for mod in con['models']:
                if mod['access'] == 'write' or mod['access'] == 'admin':
                    logger.info('Setting up Modelconnection for model: %s', mod['name'])
                    model = juju.Model_Connection(token, con['name'], mod['name'])
                    async with model.connect(token) as mod_con:
                        for a_key in current_keys:
                            logger.info('removing key: %s', a_key)
                            await mod_con.remove_ssh_key(username, a_key)
                        for r_key in new_keys:
                            logger.info('adding key: %s', r_key)
                            await mod_con.add_ssh_key(username, r_key)
        datastore.update_ssh_keys(username, new_keys)
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    ws_logger = logging.getLogger('websockets.protocol')
    logger = logging.getLogger('remove_ssh_keys')
    hdlr = logging.FileHandler('{}/log/update_ssh_keys.log'.format(sys.argv[3]))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    ws_logger.addHandler(hdlr)
    ws_logger.setLevel(logging.DEBUG)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    result = loop.run_until_complete(remove_ssh_key(sys.argv[1], sys.argv[2]))
    loop.close()
