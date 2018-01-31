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
from juju.model import Model
sys.path.append('/opt')
from sojobo_api.api import w_datastore


async def remove_machine(c_name, m_name, usr, pwd, machine):
    try:
        controller = w_datastore.get_controller(c_name)
        # We need the key of the model to get the actual model. Maybe one function
        # can be made 'get_model(m_name)'.
        m_key = w_datastore.get_model_key(c_name, m_name)
        mod = w_datastore.get_model(m_key)
        mod_con = Model()
        logger.info('Setting up Model connection for %s:%s', c_name, m_name)
        await mod_con.connect(controller['endpoints'][0], mod['uuid'], usr, pwd, controller['ca-cert'])
        for mach, entity in mod_con.state.machines.items():
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
        #if 'mod_con' in locals():
        await mod_con.disconnect()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    ws_logger = logging.getLogger('websockets.protocol')
    logger = logging.getLogger('remove-machine')
    hdlr = logging.FileHandler('{}/log/remove_machine.log'.format(sys.argv[3]))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    ws_logger.addHandler(hdlr)
    ws_logger.setLevel(logging.DEBUG)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    loop.run_until_complete(remove_machine(sys.argv[4], sys.argv[5], sys.argv[1],
                                         sys.argv[2], sys.argv[6]))
    loop.close()
