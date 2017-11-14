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
import sys
import traceback
sys.path.append('/opt')
from juju import tag
from sojobo_api import settings  #pylint: disable=C0413
from sojobo_api.api import w_datastore as datastore, w_juju as juju  #pylint: disable=C0413
from juju.client import client


class JuJu_Token(object):  #pylint: disable=R0903
    def __init__(self):
        self.username = settings.JUJU_ADMIN_USER
        self.password = settings.JUJU_ADMIN_PASSWORD
        self.is_admin = True

################################################################################
# Async method
################################################################################
async def delete_user(username):
    try:
        token = JuJu_Token()
        #TO DO => libjuju implementation
        controllers = datastore.get_all_controllers()
        datastore.set_user_state(username, 'deleting')
        for con in controllers:
            logger.info('Setting up Controllerconnection for %s', con)
            controller = juju.Controller_Connection(token, con)
            async with controller.connect(token) as con_juju:
                user_facade = client.UserManagerFacade.from_connection(con_juju.connection)
                entity = client.Entity(tag.user(username))
                logger.info('Removing user from %s', con)
                await user_facade.RemoveUser([entity])
                # if wrapper ready =>
                # await con_juju.remove(username)
            logger.info('Removed user %s from Controller %s', username ,con)
        datastore.delete_user(username)
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger('delete-user')
    ws_logger = logging.getLogger('websockets.protocol')
    hdlr = logging.FileHandler('{}/log/delete_user.log'.format(settings.SOJOBO_API_DIR))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    ws_logger.addHandler(hdlr)
    ws_logger.setLevel(logging.DEBUG)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    loop.run_until_complete(delete_user(sys.argv[1]))
    loop.close()
