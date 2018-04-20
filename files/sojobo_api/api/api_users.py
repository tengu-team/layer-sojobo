# Copyright (C) 2017 Qrama
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
# pylint: disable=c0111,c0301,c0325,c0326,w0406,e0401,e0611
###############################################################################
# USER FUNCTIONS
###############################################################################
import logging
import sys
import traceback
import base64
import hashlib
from urllib.parse import unquote
from werkzeug.exceptions import HTTPException
from flask import request, Blueprint
from sojobo_api.api import w_errors as errors, w_juju as juju
from sojobo_api.api.w_juju import execute_task


USERS = Blueprint('users', __name__)
LOGGER = logging.getLogger("api_users")
LOGGER.setLevel(logging.DEBUG)
WS_LOGGER = logging.getLogger('websockets.protocol')
WS_LOGGER.setLevel(logging.DEBUG)


def get():
    return USERS


@USERS.before_app_first_request
def initialize():
    hdlr = logging.FileHandler('/opt/sojobo_api/log/api_users.log')
    hdlr.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    LOGGER.addHandler(hdlr)
    WS_LOGGER.addHandler(hdlr)


@USERS.route('/login', methods=['POST'])
def login():
    try:
        LOGGER.info('/USERS/login [POST] => receiving call')
        print(request.headers, request.authorization)
        auth_data = juju.get_connection_info(request.authorization)
        execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data)
        code, response = 200, 'Success'
        LOGGER.info('/USERS/login [POST] => Succesfully logged in!')
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
    except HTTPException:
        ers = error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
    return juju.create_response(code, response)


@USERS.route('/', methods=['GET'])
def get_users_info():
    try:
        LOGGER.info('/USERS [GET] => receiving call')
        auth_data = juju.get_connection_info(request.authorization)
        execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data)
        LOGGER.info('/USERS [GET] => Authenticated!')
        if auth_data['company']:
            company = auth_data['company']['name']
        else:
            company = None
        if juju.check_if_admin(request.authorization, company=company):
            code, response = 200, juju.get_users_info(company)
            LOGGER.info('/USERS [GET] => Succesfully retieved all users!')
        else:
            code, response = errors.no_permission()
            LOGGER.error('/USERS [GET] => No Permission to perform this action!')
            for user in response:
                if 'controllers' in user:
                    new_controllers = []
                    for con in user['controllers']:
                        new_models = []
                        for mod in con['models']:
                            if mod['name'] != 'controller' and mod['name'] != 'default':
                                new_models.append(mod)
                        con['models'] = new_models
                        if con['name'] != 'login':
                            new_controllers.append(con)
                    user['controllers'] = new_controllers
        return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        ers = error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)


@USERS.route('/', methods=['POST'])
def create_user():
    try:
        LOGGER.info('/USERS [POST] => receiving call')
        data = request.json
        auth_data = juju.get_connection_info(request.authorization)
        execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data)
        LOGGER.info('/USERS [POST] => Authenticated!')
        if auth_data['company']:
            company = auth_data['company']['name']
        else:
            company = None
        if juju.check_if_admin(request.authorization, company=company):
            if juju.user_exists(data['username']):
                code, response = errors.already_exists('user')
                LOGGER.error('/USERS [POST] => Username %s already exists!', data['username'])
            elif data['password']:
                juju.create_user(data['username'], data['password'], company)
                code, response = 202, 'User {} is being created'.format(data['username'])
                LOGGER.info('/USERS [POST] => Creating user %s, check add_user_to_controller.log for more information!',
                            data['username'])
            else:
                code, response = errors.empty()
                LOGGER.error('/USERS [POST] => Password cannot be empty!')
        else:
            code, response = errors.no_permission()
            LOGGER.error('/USERS [POST] => No Permission to perform this action!')
        return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        ers = error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)


@USERS.route('/<user>', methods=['GET'])
def get_user_info(user):
    try:
        LOGGER.info('/USERS/%s [GET] => receiving call', user)
        auth_data = juju.get_connection_info(request.authorization)
        execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data)
        LOGGER.info('/USERS/%s [GET] => Authenticated!', user)
        if juju.authorize(auth_data, '/users/user', 'get', self_user=user, resource_user=user):
            if juju.user_exists(user):
                code, response = 200, juju.get_user_info(user)
                LOGGER.info('/USERS/%s [GET] => Succesfully retrieved user information!', user)
            else:
                code, response = errors.does_not_exist('user')
                LOGGER.error('/USERS/%s [GET] => User %s does not exist!', user, user)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/USERS/%s [GET] => No Permission to perform action!', user)
        if 'controllers' in response:
            new_controllers = []
            for con in response['controllers']:
                new_models = []
                for mod in con['models']:
                    if mod['name'] != 'controller' and mod['name'] != 'default':
                        new_models.append(mod)
                con['models'] = new_models
                if con['name'] != 'login':
                    new_controllers.append(con)
            response['controllers'] = new_controllers
        return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        ers = error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)


@USERS.route('/<user>', methods=['PUT'])
def change_user_password(user):
    try:
        LOGGER.info('/USERS/%s [PUT] => receiving call', user)
        auth_data = juju.get_connection_info(request.authorization)
        execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data)
        LOGGER.info('/USERS/%s [PUT] => Authenticated!', user)
        if juju.authorize(auth_data, '/users/user', 'put', self_user=user):
            if juju.user_exists(user):
                pwd = request.json['password']
                if pwd:
                    juju.change_user_password(user, pwd)
                    code, response = 200, 'Succesfully changed password for user {}'.format(user)
                    LOGGER.info('/USERS/%s [PUT] => Succesfully changed password for user %s!', user, user)
                else:
                    code, response = errors.empty()
                    LOGGER.error('/USERS/%s [PUT] => User password can\'t be empty!', user)
            else:
                code, response = errors.does_not_exist('user')
                LOGGER.error('/USERS/%s [PUT] => User %s does not exist!', user, user)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/USERS/%s [PUT] => No Permission to perform this action!', user)
        return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        ers = error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)


@USERS.route('/<user>', methods=['DELETE'])
def delete_user(user):
    try:
        LOGGER.info('/USERS/%s [DELETE] => receiving call', user)
        auth_data = juju.get_connection_info(request.authorization)
        execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data)
        LOGGER.info('/USERS/%s [DELETE] => Authenticated!', user)
        if auth_data['company']:
            company = auth_data['company']['name']
        else:
            company = None
        if juju.check_if_admin(request.authorization, company=company):
            if juju.user_exists(user):
                if user != 'admin':
                    juju.delete_user(user, company)
                    code, response = 202, 'User {} is being removed'.format(user)
                    LOGGER.info('/USERS/%s [DELETE] => User %s is being removed!', user, user)
                else:
                    code, response = 403, 'This would remove the Tengu admin from the system!'
                    LOGGER.error('/USERS/%s [DELETE] => This would remove the  Tengu admin from the system!', user)
            else:
                code, response = errors.does_not_exist('user')
                LOGGER.error('/USERS/%s [DELETE] => User %s does not exist!', user, user)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/USERS/%s [DELETE] => No Permission to perform this action!', user)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
    except HTTPException:
        ers = error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
    return juju.create_response(code, response)


@USERS.route('/<user>/ssh-keys', methods=['GET'])
def get_ssh_keys(user):
    try:
        LOGGER.info('/USERS/%s/ssh-keys [GET] => receiving call', user)
        auth_data = juju.get_connection_info(request.authorization)
        execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data)
        LOGGER.info('/USERS/%s/ssh-keys [GET] => Authenticated!', user)
        if juju.authorize(auth_data, '/users/user/ssh-keys', 'get', self_user=user, resource_user=user):
            if juju.user_exists(user):
                code, response = 200, juju.get_ssh_keys_user(user)
                LOGGER.info('/USERS/%s/ssh-keys [GET] => Succesfully returned ssh-keys!', user)
            else:
                code, response = errors.does_not_exist('user')
                LOGGER.error('/USERS/%s/ssh-keys [GET] => User %s does not exist!', user, user)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/USERS/%s/ssh-keys [GET] => No Permission to perform this action!', user)
        return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        ers = error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)


@USERS.route('/<user>/ssh-keys', methods=['PUT'])
def update_ssh_keys(user):
    try:
        LOGGER.info('/USERS/%s/ssh-keys [PUT] => receiving call', user)
        http_body = request.json
        auth_data = juju.get_connection_info(request.authorization)
        execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data)
        LOGGER.info('/USERS/%s/ssh-keys [PUT] => Authenticated!', user)
        if juju.authorize(auth_data, '/users/user/ssh-keys', 'put', self_user=user, resource_user=user):
            if juju.user_exists(user):
                for key in http_body['ssh-keys']:
                    try:
                        fp_key = base64.b64decode(key.strip().split()[1].encode('ascii'))
                        fp_plain = hashlib.md5(fp_key).hexdigest()
                        output = ':'.join(a+b for a,b in zip(fp_plain[::2], fp_plain[1::2]))
                    except Exception:
                        code, response = errors.invalid_ssh_key(key)
                        return juju.create_response(code, response)
                juju.update_ssh_keys_user(user, http_body['ssh-keys'])
                LOGGER.info('/USERS/%s/ssh-keys [PUT] => SSH-keys are being updated, check update_ssh_keys_all_models.log for more information!', user)
                code, response = 202, 'SSH-keys are being updated'
            else:
                code, response = errors.does_not_exist('user')
                LOGGER.error('/USERS/%s/ssh-keys [PUT] => User %s does not exist!', user, user)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/USERS/%s/ssh-keys [PUT] => No Permission to perform this action!', user)
        return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        ers = error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)


@USERS.route('/<user>/credentials', methods=['GET'])
def get_credentials(user):
    try:
        LOGGER.info('/USERS/%s/credentials [GET] => receiving call', user)
        auth_data = juju.get_connection_info(request.authorization)
        execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data)
        LOGGER.info('/USERS/%s/credentials [GET] => Authenticated!', user)
        if juju.authorize(auth_data, '/users/user/credentials', 'get', self_user=user, resource_user=user):
            if juju.user_exists(user):
                code, response = 200, juju.get_credentials(user)
                LOGGER.info('/USERS/%s/credentials [GET] => Succesfully retrieved credentials!', user)
            else:
                code, response = errors.does_not_exist('user')
                LOGGER.error('/USERS/%s/credentials [GET] => User %s does not exist!', user, user)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/USERS/%s/credentials [GET] => No Permission to perform this action!', user)
        return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        ers = error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)


@USERS.route('/<user>/credentials', methods=['POST'])
def add_credential(user):
    try:
        LOGGER.info('/USERS/%s/credentials [POST] => receiving call', user)
        credential = request.json
        auth_data = juju.get_connection_info(request.authorization)
        execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data)
        LOGGER.info('/USERS/%s/credentials [POST] => Authenticated!', user)
        if juju.authorize(auth_data, '/users/credentials', 'post', self_user=user, resource_user=user):
            if juju.user_exists(user):
                if not juju.credential_exists(user, credential['name']):
                    LOGGER.info('/USERS/%s/credentials [POST] => Adding credentials, check add_credential.log for more information!', user)
                    juju_username = juju.get_user_info(user)["juju_username"]
                    code, response = juju.add_credential(user, juju_username, request.authorization.password, credential)
                    return juju.create_response(code, response)
                else:
                    code, response = errors.already_exists('credential')
                    LOGGER.error('/USERS/%s/credentials [POST] => Credential for User %s already exists!', user, user)
                    return juju.create_response(code, response)
            else:
                code, response = errors.does_not_exist('user')
                LOGGER.error('/USERS/%s/credentials [POST] => User %s does not exist!', user, user)
                return juju.create_response(code, response)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/USERS/%s/credentials [POST] => No Permission to perform this action!', user)
            return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        ers = error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)


@USERS.route('/<user>/credentials/<credential>', methods=['GET'])
def get_credential(user, credential):
    try:
        LOGGER.info('/USERS/%s/credentials/%s [GET] => receiving call', user, credential)
        auth_data = juju.get_connection_info(request.authorization)
        execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data)
        LOGGER.info('/USERS/%s/credentials/%s [GET] => Authenticated!', user, credential)
        if juju.authorize(auth_data, '/users/credentials/credential', 'get', self_user=user, resource_user=user):
            if juju.user_exists(user):
                if juju.credential_exists(user, credential):
                    code, response = 200, juju.get_credential(user, credential)
                    LOGGER.info('/USERS/%s/credentials/%s [GET] => Succesfully retrieved credential!', user, credential)
                else:
                    code, response = errors.does_not_exist('credential')
            else:
                code, response = errors.does_not_exist('user')
                LOGGER.error('/USERS/%s/credentials/%s [GET] => User %s does not exist!', user, credential, user)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/USERS/%s/credentials/%s [GET] => No Permission to perform this action!', user, credential)
        return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        ers = error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)


@USERS.route('/<user>/credentials/<credential>', methods=['DELETE'])
def remove_credential(user, credential):
    try:
        LOGGER.info('/USERS/%s/credentials/%s [DELETE] => receiving call', user, credential)
        auth_data = juju.get_connection_info(request.authorization)
        execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data)
        LOGGER.info('/USERS/%s/credentials/%s [DELETE] => Authenticated!', user, credential)
        if juju.authorize(auth_data, '/users/credentials/credential', 'del', self_user=user, resource_user=user):
            if juju.user_exists(user):
                if juju.credential_exists(user, credential):
                    juju.remove_credential(user, credential)
                    LOGGER.info('/USERS/%s/credentials/%s [DELETE] => Removing credential, check remove_credential.log for more information!', user, credential)
                    code, response = 202, 'Credentials are being removed'
                else:
                    code, response = errors.does_not_exist('credential')
            else:
                code, response = errors.does_not_exist('user')
                LOGGER.error('/USERS/%s/credentials/%s [DELETE] => User %s does not exist!', user, credential, user)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/USERS/%s/credentials/%s [DELETE] => No Permission to perform this action!', user, credential)
        return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        ers = error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)


@USERS.route('/<user>/controllers', methods=['GET'])
def get_controllers_access(user):
    try:
        LOGGER.info('/USERS/%s/controllers [GET] => receiving call', user)
        auth_data = juju.get_connection_info(request.authorization)
        execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data)
        LOGGER.info('/USERS/%s/controllers [GET] => Authenticated', user)
        if juju.authorize(auth_data, '/users/controllers', 'get', self_user=user, resource_user=user):
            if juju.user_exists(user):
                code, response = 200, juju.get_controllers_access(user)
                LOGGER.info('/USERS/%s/controllers [GET] => Succesfully retrieved controllers access!', user)
            else:
                code, response = errors.does_not_exist('user')
                LOGGER.error('/USERS/%s/controllers [GET] => User %s does not exist', user, user)
        # elif juju.check_controllers_access(token, user)[0]:
        #         code, response = 200, juju.check_controllers_access(token, user)[1]
        #         LOGGER.info('/USERS/%s/controllers [GET] => Succesfully retrieved controllers access!', user)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/USERS/%s/controllers [GET] => No Permission to perform this action!', user)
        new_controllers = []
        for con in response:
            new_models = []
            for mod in con['models']:
                if mod['name'] != 'controller' and mod['name'] != 'default':
                    new_models.append(mod)
            con['models'] = new_models
            if con['name'] != 'login':
                new_controllers.append(con)
        response = new_controllers
        return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        ers = error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)


@USERS.route('/<user>/controllers/<controller>', methods=['GET'])
def get_ucontroller_access(user, controller):
    try:
        LOGGER.info('/USERS/%s/controllers/%s [GET] => receiving call', user, controller)
        auth_data = juju.get_connection_info(request.authorization)
        execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data)
        LOGGER.info('/USERS/%s/controllers/%s [GET] => Authenticated!', user, controller)
        if juju.authorize(auth_data, '/users/user/controllers/controller', 'get', self_user=user, resource_user=user):
            if juju.user_exists(user):
                LOGGER.info('/USERS/%s/controllers/%s [GET] => Authorized!', user, controller)
                code, response = 200, juju.get_ucontroller_access(controller, user)
                LOGGER.info('/USERS/%s/controllers/%s [GET] => Succesfully retrieved controller access!', user, controller)
            else:
                code, response = errors.does_not_exist('user')
                LOGGER.error('/USERS/%s/controllers/%s [GET] => User %s does not exist', user, controller, user)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/USERS/%s/controllers/%s [GET] => No Permission to perform this action', user, controller)
        new_models = []
        for mod in response['models']:
            if mod['name'] != 'controller' and mod['name'] != 'default':
                new_models.append(mod)
        response['models'] = new_models
        return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        ers = error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)


@USERS.route('/<user>/controllers/<controller>', methods=['PUT'])
def grant_to_controller(user, controller):
    try:
        LOGGER.info('/USERS/%s/controllers/%s [PUT] => receiving call', user, controller)
        auth_data = juju.get_connection_info(request.authorization, controller)
        connection = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data, controller)
        LOGGER.info('/USERS/%s/controllers/%s [PUT] => Authenticated!', user, controller)
        LOGGER.info('/USERS/%s/controllers/%s [PUT] => Authorized!', user, controller)
        if juju.authorize(auth_data, '/users/user/controllers/controller', 'put'):
            if juju.user_exists(user):
                if request.json['access'] and juju.c_access_exists(request.json['access'].lower()):
                    juju.grant_user_to_controller(controller, user, request.json['access'].lower())
                    LOGGER.info('/USERS/%s/controllers/%s [PUT] => Changing user access, check set_controller_access.log for more information!', user, controller)
                    code, response = 202, 'The user\'s access is being changed'
                else:
                    LOGGER.error('/USERS/%s/controllers/%s [PUT] => Invalid access data provided : %s', user, controller, request.json['access'])
                    code, response = errors.invalid_access('access')
            else:
                LOGGER.error('/USERS/%s/controllers/%s [PUT] => User %s does not exist', user, controller, user)
                code, response = errors.does_not_exist('user')
        else:
            LOGGER.error('/USERS/%s/controllers/%s [PUT] => No Permission to perform this action', user, controller)
            code, response = errors.no_permission()
        return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        ers = error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)
    finally:
        if 'connection' in locals():
            execute_task(juju.disconnect, connection)


@USERS.route('/<user>/controllers/<controller>/models', methods=['GET'])
def get_models_access(user, controller):
    try:
        LOGGER.info('/USERS/%s/controllers/%s/models [GET] => receiving call', user, controller)
        auth_data = juju.get_connection_info(request.authorization)
        execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data)
        LOGGER.info('/USERS/%s/controllers/%s/models [GET] => Authenticated!', user, controller)
        if juju.authorize(auth_data, '/users/user/controllers/controller/models', 'get', self_user=user, resource_user=user):
            if juju.user_exists(user):
                LOGGER.info('/USERS/%s/controllers/%s/models [GET] => Authorized!', user, controller)
                code, response = 200, juju.get_models_access(user, controller)
                LOGGER.info('/USERS/%s/controllers/%s/models [GET] => Succesfully retrieved models access!', user, controller)
            else:
                code, response = errors.does_not_exist('user')
                LOGGER.error('/USERS/%s/controllers/%s/models [GET] => User %s does not exist!', user, controller, user)
        # elif juju.check_models_access(token, controller, user)[0]:
        #         code, response = 200, juju.check_models_access(token, controller, user)[1]
        #         LOGGER.info('/USERS/%s/controllers/%s/models [GET] => Succesfully retrieved models access!', user, controller)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/USERS/%s/controllers/%s/models [GET] => No Permission to perform this action!', user, controller)
        new_models = []
        for mod in response:
            if mod['name'] != 'controller' and mod['name'] != 'default':
                new_models.append(mod)
        response = new_models
        return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        ers = error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)


@USERS.route('/<user>/controllers/<controller>/models', methods=['PUT'])
def grant_to_model(user, controller):
    try:
        LOGGER.info('/USERS/%s/controllers/%s/models [PUT] => receiving call', user, controller)
        models_access_levels = request.json
        auth_data = juju.get_connection_info(request.authorization)
        execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data)
        LOGGER.info('/USERS/%s/controllers/%s/models [PUT] => Authenticated!', user, controller)
        LOGGER.info('/USERS/%s/controllers/%s/models [PUT] => Authorized!', user, controller)
        if juju.authorize(auth_data, '/users/user/controllers/controller/models', 'put'):
            if juju.user_exists(user):
                juju.set_models_access(user, controller, models_access_levels)
                LOGGER.info('/USERS/%s/controllers/%s/models [PUT] => Setting model access, check set_model_access.log for more information!', user, controller)
                code, response = 202, 'The model access is being changed'
            else:
                code, response = errors.does_not_exist('user')
                LOGGER.error('/USERS/%s/controllers/%s/models [PUT] => User %s does not exist!', user, controller, user)
        else:
            LOGGER.error('/USERS/%s/controllers/%s/models [PUT] => No Permission to perform this action!', user, controller)
            code, response = errors.no_permission()
        return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        ers = error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)


@USERS.route('/<user>/controllers/<controller>/models/<model>', methods=['GET'])
def get_model_access(user, controller, model):
    try:
        model = unquote(model)
        LOGGER.info('/USERS/%s/controllers/%s/models/%s [GET] => receiving call!', user, controller, model)
        auth_data = juju.get_connection_info(request.authorization)
        execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data)
        LOGGER.info('/USERS/%s/controllers/%s/models/%s [GET] => Authenticated!', user, controller, model)
        LOGGER.info('/USERS/%s/controllers/%s/models/%s [GET] => Authorized!', user, controller, model)
        if juju.authorize(auth_data, '/users/user/controllers/controller/models/model', 'get', self_user=user, resource_user=user):
            if juju.user_exists(user):
                access = juju.get_model_access(model, controller, user)
                code, response = 200, {'access' : access}
                LOGGER.info('/USERS/%s/controllers/%s/models/%s [GET] => Succesfully retrieved model access!', user, controller, model)
            else:
                code, response = errors.does_not_exist('user')
                LOGGER.error('/USERS/%s/controllers/%s/models/%s [GET] => User %s does not exist!', user, controller, model, user)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/USERS/%s/controllers/%s/models/%s [GET] => No Permission to perform this action!', user, controller, model)

    except KeyError:
        code, response = errors.invalid_data()
        error_log()
    except HTTPException:
        ers = error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
    return juju.create_response(code, response)

def error_log():
    exc_type, exc_value, exc_traceback = sys.exc_info()
    lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
    for l in lines:
        LOGGER.error(l)
    return lines
