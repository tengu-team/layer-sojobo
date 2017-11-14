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
import re
import sys
import traceback
import base64, hashlib
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
        execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
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
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/USERS [GET] => Authenticated!')
        code, response = 200, juju.get_users_info(token)
        LOGGER.info('/USERS [GET] => Succesfully retieved all users!')
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

@USERS.route('/', methods=['POST'])
def create_user():
    try:
        LOGGER.info('/USERS [POST] => receiving call')
        data = request.json
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/USERS [POST] => Authenticated!')
        valid, user = juju.check_input(data['username'], "username")
        if token.is_admin:
            if valid:
                if juju.user_exists(user):
                    code, response = errors.already_exists('user')
                    LOGGER.error('/USERS [POST] => Username %s already exists!', user)
                elif data['password']:
                    LOGGER.info('/USERS [POST] => Creating user %s, check add_user.log for more information!', user)
                    juju.create_user(user, data['password'])
                    code, response = 202, 'User {} is being created'.format(user)
                else:
                    code, response = errors.empty()
                    LOGGER.error('/USERS [POST] => Password cannot be empty!')
            else:
                code, response = 400, user
                LOGGER.error('/USERS [POST] => Username does not have the correct format!')
        else:
            code, response = errors.no_permission()
            LOGGER.error('/USERS [POST] => No Permission to perform this action!')
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


@USERS.route('/<user>', methods=['GET'])
def get_user_info(user):
    try:
        LOGGER.info('/USERS/%s [GET] => receiving call', user)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/USERS/%s [GET] => Authenticated!', user)
        if user == token.username or token.is_admin:
            if juju.user_exists(user):
                code, response = 200, juju.get_user_info(user)
                LOGGER.info('/USERS/%s [GET] => Succesfully retrieved user information!', user)
            else:
                code, response = errors.does_not_exist('user')
                LOGGER.error('/USERS/%s [GET] => User %s does not exist!', user, user)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/USERS/%s [GET] => No Permission to perform action!', user)
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


@USERS.route('/<user>', methods=['PUT'])
def change_user_password(user):
    try:
        LOGGER.info('/USERS/%s [PUT] => receiving call', user)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/USERS/%s [PUT] => Authenticated!', user)
        if user == token.username or token.is_admin:
            if juju.user_exists(user):
                pwd = request.json['password']
                if pwd:
                    execute_task(juju.change_user_password, token, user, pwd)
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


@USERS.route('/<user>', methods=['DELETE'])
def delete_user(user):
    try:
        LOGGER.info('/USERS/%s [DELETE] => receiving call', user)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/USERS/%s [DELETE] => Authenticated!', user)
        if token.is_admin:
            if juju.user_exists(user):
                if user != 'admin':
                    juju.delete_user(user)
                    code, response = 202, 'User {} is being removed'.format(user)
                    LOGGER.info('/USERS/%s [DELETE] => User %s is being removed!', user, user)
                else:
                    code, response = 403, 'This would remove the admin from the system!'
                    LOGGER.error('/USERS/%s [DELETE] => This would remove the admin from the system!', user)
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
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/USERS/%s/ssh-keys [GET] => Authenticated!', user)
        if token.is_admin or token.username == user:
            if juju.user_exists(user):
                code, response = 200, juju.get_ssh_keys_user(user)
                LOGGER.info('/USERS/%s/ssh-keys [GET] => Succesfully returned ssh-keys!', user)
            else:
                code, response = errors.does_not_exist('user')
                LOGGER.error('/USERS/%s/ssh-keys [GET] => User %s does not exist!', user, user)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/USERS/%s/ssh-keys [GET] => No Permission to perform this action!', user)
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


@USERS.route('/<user>/ssh-keys', methods=['PUT'])
def update_ssh_keys(user):
    try:
        LOGGER.info('/USERS/%s/ssh-keys [PUT] => receiving call', user)
        data = request.json
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/USERS/%s/ssh-keys [PUT] => Authenticated!', user)
        if token.is_admin or token.username == user:
            if juju.user_exists(user):
                for key in data['ssh-keys']:
                    try:
                        fp_key = base64.b64decode(key.strip().split()[1].encode('ascii'))
                        fp_plain = hashlib.md5(fp_key).hexdigest()
                        output = ':'.join(a+b for a,b in zip(fp_plain[::2], fp_plain[1::2]))
                    except Exception:
                        code, response = errors.invalid_ssh_key(key)
                        return juju.create_response(code, response)
                juju.update_ssh_keys_user(user, data['ssh-keys'])
                LOGGER.info('/USERS/%s/ssh-keys [PUT] => SSH-keys are being updated, check update_ssh_keys.log for more information!', user)
                code, response = 202, 'SSH-keys are being updated'
            else:
                code, response = errors.does_not_exist('user')
                LOGGER.error('/USERS/%s/ssh-keys [PUT] => User %s does not exist!', user, user)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/USERS/%s/ssh-keys [PUT] => No Permission to perform this action!', user)
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


@USERS.route('/<user>/credentials', methods=['GET'])
def get_credentials(user):
    try:
        LOGGER.info('/USERS/%s/credentials [GET] => receiving call', user)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/USERS/%s/credentials [GET] => Authenticated!', user)
        if token.is_admin or token.username == user:
            if juju.user_exists(user):
                code, response = 200, juju.get_credentials(user)
                LOGGER.info('/USERS/%s/credentials [GET] => Succesfully retrieved credentials!', user)
            else:
                code, response = errors.does_not_exist('user')
                LOGGER.error('/USERS/%s/credentials [GET] => User %s does not exist!', user, user)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/USERS/%s/credentials [GET] => No Permission to perform this action!', user)
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


@USERS.route('/<user>/credentials', methods=['POST'])
def add_credential(user):
    try:
        LOGGER.info('/USERS/%s/credentials [POST] => receiving call', user)
        data = request.json
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/USERS/%s/credentials [POST] => Authenticated!', user)
        if token.is_admin or token.username == user:
            if juju.user_exists(user):
                if not juju.credential_exists(user, data['name']):
                    juju.add_credential(user, data)
                    LOGGER.info('/USERS/%s/credentials [POST] => Adding credentials, check add_credential.log for more information!', user)
                    code, response = 202, 'Credentials are being added'
                else:
                    code, response = errors.already_exists('credential')
                    LOGGER.error('/USERS/%s/credentials [POST] => Credential for User %s already exists!', user, user)
            else:
                code, response = errors.does_not_exist('user')
                LOGGER.error('/USERS/%s/credentials [POST] => User %s does not exist!', user, user)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/USERS/%s/credentials [POST] => No Permission to perform this action!', user)
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

@USERS.route('/<user>/credentials/<credential>', methods=['GET'])
def get_credential(user, credential):
    try:
        LOGGER.info('/USERS/%s/credentials/%s [GET] => receiving call', user, credential)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/USERS/%s/credentials/%s [GET] => Authenticated!', user, credential)
        if token.is_admin or token.username == user:
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

@USERS.route('/<user>/credentials/<credential>', methods=['DELETE'])
def remove_credential(user, credential):
    try:
        LOGGER.info('/USERS/%s/credentials/%s [DELETE] => receiving call', user, credential)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/USERS/%s/credentials/%s [DELETE] => Authenticated!', user, credential)
        if token.is_admin or token.username == user:
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


@USERS.route('/<user>/controllers', methods=['GET'])
def get_controllers_access(user):
    try:
        LOGGER.info('/USERS/%s/controllers [GET] => receiving call', user)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/USERS/%s/controllers [GET] => Authenticated', user)
        if token.is_admin or token.username == user:
            if juju.user_exists(user):
                code, response = 200, juju.get_controllers_access(user)
                LOGGER.info('/USERS/%s/controllers [GET] => Succesfully retrieved controllers access!', user)
            else:
                code, response = errors.does_not_exist('user')
                LOGGER.error('/USERS/%s/controllers [GET] => User %s does not exist', user, user)
        elif juju.check_controllers_access(token, user)[0]:
                code, response = 200, juju.check_controllers_access(token, user)[1]
                LOGGER.info('/USERS/%s/controllers [GET] => Succesfully retrieved controllers access!', user)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/USERS/%s/controllers [GET] => No Permission to perform this action!', user)
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


@USERS.route('/<user>/controllers/<controller>', methods=['GET'])
def get_ucontroller_access(user, controller):
    try:
        LOGGER.info('/USERS/%s/controllers/%s [GET] => receiving call', user, controller)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/USERS/%s/controllers/%s [GET] => Authenticated!', user, controller)
        con = juju.authorize(token, controller)
        if token.is_admin or token.username == user or con.access == 'superuser':
            if juju.user_exists(user):
                LOGGER.info('/USERS/%s/controllers/%s [GET] => Authorized!', user, controller)
                code, response = 200, juju.get_ucontroller_access(con, user)
                LOGGER.info('/USERS/%s/controllers/%s [GET] => Succesfully retrieved controller access!', user, controller)
            else:
                code, response = errors.does_not_exist('user')
                LOGGER.error('/USERS/%s/controllers/%s [GET] => User %s does not exist', user, controller, user)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/USERS/%s/controllers/%s [GET] => No Permission to perform this action', user, controller)
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


@USERS.route('/<user>/controllers/<controller>', methods=['PUT'])
def grant_to_controller(user, controller):
    try:
        LOGGER.info('/USERS/%s/controllers/%s [PUT] => receiving call', user, controller)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/USERS/%s/controllers/%s [PUT] => Authenticated!', user, controller)
        con = juju.authorize(token, controller)
        LOGGER.info('/USERS/%s/controllers/%s [PUT] => Authorized!', user, controller)
        if (token.is_admin or con.c_access == 'superuser') and 'admin' != user:
            if juju.user_exists(user):
                if request.json['access'] and juju.c_access_exists(request.json['access'].lower()):
                    juju.grant_user_to_controller(token, con, user, request.json['access'].lower())
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


@USERS.route('/<user>/controllers/<controller>/models', methods=['GET'])
def get_models_access(user, controller):
    try:
        LOGGER.info('/USERS/%s/controllers/%s/models [GET] => receiving call', user, controller)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/USERS/%s/controllers/%s/models [GET] => Authenticated!', user, controller)
        con = juju.authorize(token, controller)
        if token.is_admin or token.username == user or con.access == 'superuser':
            if juju.user_exists(user):
                LOGGER.info('/USERS/%s/controllers/%s/models [GET] => Authorized!', user, controller)
                code, response = 200, juju.get_models_access(con, user)
                LOGGER.info('/USERS/%s/controllers/%s/models [GET] => Succesfully retrieved models access!', user, controller)
            else:
                code, response = errors.does_not_exist('user')
                LOGGER.error('/USERS/%s/controllers/%s/models [GET] => User %s does not exist!', user, controller, user)
        elif juju.check_models_access(token, controller, user)[0]:
                code, response = 200, juju.check_models_access(token, controller, user)[1]
                LOGGER.info('/USERS/%s/controllers/%s/models [GET] => Succesfully retrieved models access!', user, controller)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/USERS/%s/controllers/%s/models [GET] => No Permission to perform this action!', user, controller)
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


@USERS.route('/<user>/controllers/<controller>/models', methods=['PUT'])
def grant_to_model(user, controller):
    try:
        LOGGER.info('/USERS/%s/controllers/%s/models [PUT] => receiving call', user, controller)
        data = request.json
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/USERS/%s/controllers/%s/models [PUT] => Authenticated!', user, controller)
        con = juju.authorize(token, controller)
        LOGGER.info('/USERS/%s/controllers/%s/models [PUT] => Authorized!', user, controller)
        if (token.is_admin or con.c_access == 'superuser') and 'admin' != user:
            if juju.user_exists(user):
                juju.set_models_access(token, con, user, data)
                LOGGER.info('/USERS/%s/controllers/%s/models [PUT] => Setting model access, check set_model_access.log for more information!', user, controller)
                code, response = 202, 'The model access is being changed'
            else:
                code, response = errors.does_not_exist('user')
                LOGGER.error('/USERS/%s/controllers/%s/models [PUT] => User %s does not exist!', user, controller, user)
        else:
            user_access = juju.get_models_access(con, user)
            if juju.user_exists(user):
                for mod in data:
                    if not mod['name'] in user_access:
                        LOGGER.error('/USERS/%s/controllers/%s/models [PUT] => No Permission to perform this action!', user, controller)
                        code, response = errors.no_permission()
                        return juju.create_response(code, response)
                juju.set_models_access(token, con, user, data)
                LOGGER.info('/USERS/%s/controllers/%s/models [PUT] => Setting model access, check set_model_access.log for more information!', user, controller)
                code, response = 202, 'The model access is being changed'
            else:
                code, response = errors.does_not_exist('user')
                LOGGER.error('/USERS/%s/controllers/%s/models [PUT] => User %s does not exist!', user, controller, user)
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


@USERS.route('/<user>/controllers/<controller>/models/<model>', methods=['GET'])
def get_model_access(user, controller, model):
    try:
        LOGGER.info('/USERS/%s/controllers/%s/models/%s [GET] => receiving call!', user, controller, model)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/USERS/%s/controllers/%s/models/%s [GET] => Authenticated!', user, controller, model)
        con, mod = juju.authorize(token, controller, model)
        LOGGER.info('/USERS/%s/controllers/%s/models/%s [GET] => Authorized!', user, controller, model)
        if token.is_admin or token.username == user or mod.access == 'admin' or con.access == 'superuser':
            if juju.user_exists(user):
                access = juju.get_model_access(mod.m_name, con.c_name, user)
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
