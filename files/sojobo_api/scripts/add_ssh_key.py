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
# pylint: disable=c0111,c0301,c0325,c0103,r0913,r0902,e0401,C0302,R0914
import asyncio
import sys
import traceback
import logging
import json
import redis
from juju.model import Model


async def add_ssh_key(usr, pwd, ssh_key, url, port, username):
    try:
        controllers = redis.StrictRedis(host=url, port=port, charset="utf-8", decode_responses=True, db=10)
        users = redis.StrictRedis(host=url, port=port, charset="utf-8", decode_responses=True, db=11)
        user = json.loads(users.get(username))
        if ssh_key not in user['ssh-keys']:
            user['ssh-keys'].append(ssh_key)
            users.set(username, json.dumps(user))
            for con in user['controllers']:
                for mod in con['models']:
                    if mod['access'] == 'write' or mod['access'] == 'admin':
                        model = Model()
                        logger.info('Setting up Modelconnection for model: %s', mod['name'])
                        controller = json.loads(controllers.get(con['name']))
                        for modl in controller['models']:
                            if modl['name'] == mod['name']:
                                await model.connect(controller['endpoints'][0], modl['uuid'],
                                                    usr, pwd, controller['ca-cert'])
                                await model.add_ssh_key(username, ssh_key)
                                await model.disconnect()
                                break
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)


if __name__ == '__main__':
    logger = logging.getLogger('add_ssh_keys')
    hdlr = logging.FileHandler('{}/log/add_ssh_keys.log'.format(sys.argv[3]))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    loop.run_until_complete(add_ssh_key(sys.argv[1], sys.argv[2], sys.argv[4], sys.argv[5],
                                         sys.argv[6], sys.argv[7]))
    loop.close()
