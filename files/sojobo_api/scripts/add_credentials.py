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

import redis
################################################################################
# Asyncio Wrapper
################################################################################
def execute_task(command, *args):
    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    result = loop.run_until_complete(command(*args))
    return result

################################################################################
# Datastore Functions
################################################################################
def get_credentials(user, connection):
    data = connection.get(user)
    return data['credentials']


def write_credentials(user, creds, connection):
    data = connection.get(user)
    credlist = data['credentials']
    credlist.append(creds)
    data['credentials'] = credlist
    connection.set(user, data)
    logger.info('Succesfully added credentials for %s', username)

################################################################################
# Async Functions
################################################################################
async def add_credentials(username, credentials, url, port):
    try:
        logger.info('Setting up connection with Redis')
        db = redis.StrictRedis(host=url, port=port, db=11)
        #checken op name en dan anders toevoegen
        for cred in get_credentials(username, db):
            if not credentials['tag'] == cred['tag']:
                write_credentials(username, credentials, db)
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)

if __name__ == '__main__':
    username, api_dir, credentials, url, port = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
    logger = logging.getLogger('add_credentials')
    hdlr = logging.FileHandler('{}/log/add_credentials.log'.format(api_dir))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    execute_task(add_credentials, username, credentials, url, port)
