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
sys.path.append('/opt')
from sojobo_api import settings  #pylint: disable=C0413
from sojobo_api.api import w_datastore as datastore, w_juju as juju  #pylint: disable=C0413


class JuJu_Token(object):  #pylint: disable=R0903
    def __init__(self):
        self.username = settings.JUJU_ADMIN_USER
        self.password = settings.JUJU_ADMIN_PASSWORD
        self.is_admin = True

async def set_controller_acc(c_name, access, user):
    try:
        token = JuJu_Token()
        con = datastore.get_controller(c_name)
        usr = datastore.get_user(user)
        logger.info('Connecting to controller %s', c_name)
        controller = juju.Controller_Connection(token, c_name)
        async with controller.connect(token) as con_juju:
            logger.info('Connected to controller %s ', c_name)
            await con_juju.grant(user, acl=access)
            datastore.set_controller_access(c_name, user, access)
        logger.info('Controller access set for  %s ', c_name)
        if access == 'superuser':
            for mod in con['models']:
                model = juju.Model_Connection(token, con['name'], mod['name'])
                async with model.connect(token) as mod_con:
                    logger.info('Setting up connection for model: %s', mod['name'])
                    current_access = datastore.get_model_access(c_name, mod['name'], user)
                    logger.info('Current Access level: %s', current_access)
                    if current_access:
                        await mod_con.revoke(user)
                    await mod_con.grant(user, acl='admin')
                    datastore.set_model_access(c_name, mod['name'], user, 'admin')
                    logger.info('Admin Access granted for for %s:%s', c_name, mod['name'])
                for key in usr['ssh-keys']:
                    logger.info('SSh key found... adding SSH key %s', key)
                    await mod_con.add_ssh_key(user, key)
    except Exception:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    ws_logger = logging.getLogger('websockets.protocol')
    logger = logging.getLogger('set_controller_access')
    hdlr = logging.FileHandler('{}/log/set_controller_access.log'.format(sys.argv[3]))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    ws_logger.addHandler(hdlr)
    ws_logger.setLevel(logging.DEBUG)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    result = loop.run_until_complete(set_controller_acc(sys.argv[1], sys.argv[2], sys.argv[4]))
    loop.close()
