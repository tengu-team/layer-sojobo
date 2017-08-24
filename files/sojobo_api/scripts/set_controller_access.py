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
# pylint: disable=c0111,c0301,c0325,c0103,r0204,r0913,r0902,e0401,C0302, R0914
import asyncio
import sys
import traceback
import logging
import json
import redis
from juju.model import Model
from juju.controller import Controller


async def set_controller_acc(c_name, access, user, username, password, url, port):
    try:
        controllers = redis.StrictRedis(host=url, port=port, charset="utf-8", decode_responses=True, db=10)
        users = redis.StrictRedis(host=url, port=port, charset="utf-8", decode_responses=True, db=11)
        con = json.loads(controllers.get(c_name))
        usr = json.loads(users.get(user))
        logger.info('Connecting to controller %s', c_name)
        controller = Controller()
        await controller.connect(con['endpoints'][0], username, password, con['ca-cert'])
        logger.info('Connected to controller %s ', c_name)
        await controller.grant(user, acl=access)
        exists = False
        for contr in usr['controllers']:
            if contr['name'] == c_name:
                contr['access'] = access
                exists = True
                break
        if not exists:
            usr['controllers'].append({'name': c_name, 'access': access})
        logger.info('Controller access set for  %s ', c_name)
        if access == 'superuser':
            model = Model()
            models = []
            for mod in con['models']:
                logger.info('Setting up connection for model: %s', mod['name'])
                await model.connect(con['endpoints'][0], mod['uuid'], username, password, con['ca-cert'])
                await model.grant(user, acl='admin')
                models.append({'name': mod['name'], 'access': 'admin'})
                logger.info('Admin Access granted for for %s:%s', c_name, mod['name'])
                for key in usr['ssh-keys']:
                    await model.add_ssh_key(user, key)
                model.disconnect()
            for contro in usr['controllers']:
                if contro['name'] == c_name:
                    contro['models'] = models
        users.set(user, json.dumps(usr))
        controller.disconnect()
    except Exception:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)


if __name__ == '__main__':
    logger = logging.getLogger('set_controller_access')
    hdlr = logging.FileHandler('{}/log/set_controller_access.log'.format(sys.argv[3]))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    result = loop.run_until_complete(set_controller_acc(sys.argv[8], sys.argv[7], sys.argv[6],
                                                        sys.argv[1], sys.argv[2], sys.argv[4], sys.argv[5]))
    loop.close()
