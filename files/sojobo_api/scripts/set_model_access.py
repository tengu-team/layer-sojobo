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
import traceback
import logging
import json
import redis
from juju.model import Model
from juju.controller import Controller


async def set_model_acc(c_name, m_name, access, user, username, password, url, port):
    try:
        controllers = redis.StrictRedis(host=url, port=port, charset="utf-8", decode_responses=True, db=10)
        users = redis.StrictRedis(host=url, port=port, charset="utf-8", decode_responses=True, db=11)
        controller = json.loads(controllers.get(c_name))
        usr = json.loads(users.get(user))
        for mod in controller['models']:
            if mod['name'] == m_name:
                model = Model()
                await model.connect(controller['endpoints'][0], mod['uuid'], username, password, controller['ca-cert'])
                await model.grant(user, acl=access)
                exists_con = False
                for con in usr['controllers']:
                    if con['name'] == c_name:
                        exists_mod = False
                        exists_con = True
                        for mod in con['models']:
                            if mod['name'] == m_name:
                                mod['access'] = access
                                exists_mod = True
                                break
                        if not exists_mod:
                            con['models'].append({'name': m_name, 'access': access})
                if not exists_con:
                    usr['controllers'].append({'name': c_name, 'access': 'login', 'models': [{'name': m_name, 'access': access}]})
                    contro = Controller()
                    await contro.connect(controller['endpoints'][0], username, password, controller['ca-cert'])
                    await contro.grant(user)
                    await contro.disconnect()
                logger.info('%s access granted on %s:%s for  %s', access, c_name, m_name, user)
                if access == 'admin' or access == 'write':
                    for key in usr['ssh-keys']:
                        await model.add_ssh_key(user, key)
                model.disconnect()
        controllers.set(c_name, json.dumps(controller))
        users.set(user, json.dumps(usr))
    except Exception:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)


if __name__ == '__main__':
    logger = logging.getLogger('set_model_access')
    hdlr = logging.FileHandler('{}/log/set_model_access.log'.format(sys.argv[3]))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    result = loop.run_until_complete(set_model_acc(sys.argv[8], sys.argv[9], sys.argv[7],
                                                   sys.argv[6], sys.argv[1], sys.argv[2],
                                                   sys.argv[4], sys.argv[5]))
    loop.close()
