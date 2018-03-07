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
from juju import tag, errors
from juju.client import client
from juju.controller import Controller
sys.path.append('/opt')
from sojobo_api import settings  #pylint: disable=C0413
from sojobo_api.api import w_datastore as datastore, w_juju as juju  #pylint: disable=C0413

async def set_controller_acc(c_name, username, acl):
    try:
        controller_ds = datastore.get_controller(c_name)
        user_ds = datastore.get_user(username)

        logger.info('Setting up Controller connection for %s.', controller_ds['name'])
        controller_connection = Controller()
        await controller_connection.connect(endpoint=controller_ds['endpoints'][0],
                                            username=settings.JUJU_ADMIN_USER,
                                            password=settings.JUJU_ADMIN_PASSWORD,
                                            cacert=controller_ds['ca_cert'])
        logger.info('Controller connection as admin was successful.')

        logger.info('Initializing facade...')
        controller_facade = client.ControllerFacade.from_connection(controller_connection.connection())
        juju_user = tag.user(user_ds["juju_username"])

        # Note that if the user already has higher permissions than the
        # provided ACL, this will do nothing so first we need to revoke access.
        logger.info('Revoking access before granting new access...')
        changes = client.ModifyControllerAccess(acl, 'revoke', juju_user)
        await controller_facade.ModifyControllerAccess([changes])

        changes = client.ModifyControllerAccess(acl, 'grant', juju_user)
        try:
            logger.info('Trying to grant controller access to %s for controller %s...', acl, c_name)
            await controller_facade.ModifyControllerAccess([changes])
            datastore.set_controller_access(c_name, username, acl)
            logger.info('Controller access %s granted on %s!', acl, c_name)
        except errors.JujuError as e:
            if 'user already has' in str(e):
                logger.info('User already has the access level %s on the controller %s ',
                acl, c_name)
            else:
                raise

        # If a user becomes a superuser of a certain controller then the user must
        # also get admin access over the models that belong to that controller.
        # if acl == 'superuser':
        #     print("===== Access is superuser =====")
        #     for mod in datastore.get_all_models(c_name):
        #         print("===== Model =====")
        #         model = juju.Model_Connection(token, controller_ds['name'], mod['name'])
        #         print(model)
        #         async with model.connect(token) as mod_con:
        #             logger.info('Setting up connection for model: %s', mod['name'])
        #             current_access = datastore.get_model_access(c_name, mod['name'], user)
        #             logger.info('Current Access level: %s', current_access)
        #             if current_access:
        #                 print("===== REVOKING =====")
        #                 await mod_con.revoke(user)
        #                 print("===== DONE REVOKING =====")
        #             print("===== GRANTING ADMIN RIGHTS =====")
        #             await mod_con.grant(user, acl='admin')
        #             print("===== DONE GRANTING =====")
        #             datastore.set_model_access(mod["_key"], user, 'admin')
        #             logger.info('Admin Access granted for for %s:%s', c_name, mod['name'])
        #             for key in usr['ssh_keys']:
        #                 logger.info('SSh key found... adding SSH key %s', key)
        #                 await mod_con.add_ssh_key(user, key)

    except Exception:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        for l in lines:
            logger.error(l)
    finally:
        await juju.disconnect(controller_connection)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    ws_logger = logging.getLogger('websockets.protocol')
    logger = logging.getLogger('set_controller_access')
    hdlr = logging.FileHandler('{}/log/set_controller_access.log'.format(sys.argv[4]))
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    ws_logger.addHandler(hdlr)
    ws_logger.setLevel(logging.DEBUG)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    loop.set_debug(True)
    result = loop.run_until_complete(set_controller_acc(sys.argv[1], sys.argv[2],
                                                        sys.argv[3]))
    loop.close()
