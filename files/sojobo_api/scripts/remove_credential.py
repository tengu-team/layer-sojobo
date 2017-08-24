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


async def remove_credential(username, cred_name, url, port):
    try:
        logger.info('Setting up connection with Redis')
        db = redis.StrictRedis(host=url, port=port, charset="utf-8", decode_responses=True, db=11)
        usr = json.loads(db.get(username))
        for cred in usr['credentials']:
            if cred['name'] == cred_name:
                usr['credentials'].remove(cred)
                db.set(username, json.dumps(usr))
                break
        logger.info('Succesfully removed credential for %s', username)
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)


if __name__ == '__main__':
    logger = logging.getLogger('add_credentials')
    hdlr = logging.FileHandler('{}/log/add_credentials.log'.format(sys.argv[2]))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    loop.run_until_complete(remove_credential(sys.argv[1], sys.argv[3], sys.argv[4], sys.argv[5]))
    loop.close()
