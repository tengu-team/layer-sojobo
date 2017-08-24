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
import json
import redis
from juju.model import Model


async def remove_machine(c_name, m_name, usr, pwd, url, port, machine):
    try:
        controllers = redis.StrictRedis(host=url, port=port, charset="utf-8", decode_responses=True, db=10)
        controller = json.loads(controllers.get(c_name))
        model = Model()
        logger.info('Setting up Model connection for %s:%s', c_name, m_name)
        for mod in controller['models']:
            if mod['name'] == m_name:
                await model.connect(controller['endpoints'][0], mod['uuid'], usr, pwd, controller['ca-cert'])
                for mach, entity in model.state.machines.items():
                    if mach == machine:
                        logger.info('Destroying machine %s', machine)
                        await entity.destroy(force=True)
        logger.info('Machine %s destroyed', machine)
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)
    finally:
        if 'model' in locals():
            await model.disconnect()


if __name__ == '__main__':
    logger = logging.getLogger('remove-machine')
    hdlr = logging.FileHandler('{}/log/remove_machine.log'.format(sys.argv[3]))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    loop.run_until_complete(remove_machine(sys.argv[6], sys.argv[7], sys.argv[1],
                                         sys.argv[2], sys.argv[4], sys.argv[5], sys.argv[8]))
    loop.close()
