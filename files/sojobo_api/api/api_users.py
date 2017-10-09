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
        code, response = 200, execute_task(juju.get_users_info, token)
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
        user = data['username']
        m = re.match('^[0-9a-zA-Z]([0-9a-zA-Z.-]*[0-9a-zA-Z])$', user)
        if not(m) and m.end() != len(user):
            code, response = 400, "username does not have the correct format."
            LOGGER.error('/USERS [POST] => Username does not have the correct format!')
        elif token.is_admin:
            if execute_task(juju.user_exists, user):
                code, response = errors.already_exists('user')
                LOGGER.error('/USERS [POST] => Username %s already exists!', user)
            elif data['password']:
                execute_task(juju.create_user, token, user, data['password'])
                LOGGER.info('/USERS [POST] => Creating user %s, check add_user.log for more information!', user)
                code, response = 202, 'User {} is being created'.format(user)
            else:
                code, response = errors.empty()
                LOGGER.error('/USERS [POST] => Username can not be empty!')
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
            if execute_task(juju.user_exists, user):
                code, response = 200, execute_task(juju.get_user_info, user)
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
            if execute_task(juju.user_exists, user):
                pwd = request.json['password']
                if pwd:
                    execute_task(juju.change_user_password, token, user, pwd)
                    code, response = 200, 'succesfully changed password for user {}'.format(user)
                    LOGGER.info('/USERS/%s [PUT] => succesfully changed password for user %s!', user, user)
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
            if execute_task(juju.user_exists, user):
                if user != 'admin':
                    execute_task(juju.delete_user, token, user)
                    code, response = 200, 'User {} succesfully removed'.format(user)
                    LOGGER.info('/USERS/%s [DELETE] => User %s succesfully removed!', user, user)
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
            code, response = 200, execute_task(juju.get_ssh_keys_user, user)
            LOGGER.info('/USERS/%s/ssh-keys [GET] => Succesfully  ssh-keys!', user)
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
        user = juju.check_input(user)
        LOGGER.info('/USERS/%s/ssh-keys [PUT] => Authenticated!', user)
        if token.is_admin or token.username == user:
            execute_task(juju.update_ssh_keys_user, user, data)
            LOGGER.info('/USERS/%s/ssh-keys [PUT] => SH-keys are being updated, check update_ssh_keys.log for more information!', user)
            code, response = 202, 'Process being handled'
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
        usr = juju.check_input(user)
        if token.is_admin or token.username == usr:
            code, response = 200, juju.execute_task(juju.get_credentials, token, usr)
            LOGGER.info('/USERS/%s/credentials [GET] => Succesfully retrieved credentials!', user)
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
        usr = juju.check_input(user)
        if token.is_admin or token.username == usr:
            execute_task(juju.add_credential, usr, data['type'], data['name'], data['credential'])
            LOGGER.info('/USERS/%s/credentials [POST] => Adding credentials, check add_credential.log for more information!', user)
            code, response = 202, 'Process being handled'
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
        data = request.json
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/USERS/%s/credentials/%s [GET] => Authenticated!', user, credential)
        usr = juju.check_input(user)
        if token.is_admin or token.username == usr:
            code, response = 200, execute_task(juju.get_credential, usr, data['name'], credential)
            LOGGER.info('/USERS/%s/credentials/%s [GET] => Succesfully retrieved credential!', user, credential)
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
        data = request.json
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/USERS/%s/credentials/%s [DELETE] => Authenticated!', user, credential)
        usr = juju.check_input(user)
        if token.is_admin or token.username == usr:
            execute_task(juju.remove_credential, usr, data['name'], credential)
            LOGGER.info('/USERS/%s/credentials/%s [DELETE] => Removing credential, check remove_credential.log for more information!', user, credential)
            code, response = 202, 'Process being handled'
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
        if execute_task(juju.user_exists, user):
            if token.is_admin or token.username == user:
                code, response = 200, execute_task(juju.get_controllers_access, user)
                LOGGER.info('/USERS/%s/controllers [GET] => Succesfully retrieved controllers access!', user)
            else:
                code, response = errors.no_permission()
                LOGGER.error('/USERS/%s/controllers [GET] => No Permission to perform this action!', user)
        else:
            code, response = errors.does_not_exist('user')
            LOGGER.error('/USERS/%s/controllers [GET] => User %s does not exist', user, user)
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
        if execute_task(juju.user_exists, user):
            if token.is_admin or token.username == user:
                con = execute_task(juju.authorize, token, controller)
                LOGGER.info('/USERS/%s/controllers/%s [GET] => Authorized!', user, controller)
                code, response = 200, execute_task(juju.get_ucontroller_access, con, user)
                LOGGER.info('/USERS/%s/controllers/%s [GET] => Succesfully retrieved controller access!', user, controller)
            else:
                code, response = errors.no_permission()
                LOGGER.error('/USERS/%s/controllers/%s [GET] => No Permission to perform this action', user, controller)
        else:
            code, response = errors.does_not_exist('user')
            LOGGER.error('/USERS/%s/controllers/%s [GET] => User %s does not exist', user, controller, user)
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
        con = execute_task(juju.authorize, token, juju.check_input(controller))
        LOGGER.info('/USERS/%s/controllers/%s [PUT] => Authorized!', user, controller)
        if execute_task(juju.user_exists, user):
            if (token.is_admin or con.c_access == 'superuser') and user != 'admin':
                access = juju.check_access(request.json['access'])
                execute_task(juju.grant_user_to_controller, token, con, user, access)
                LOGGER.info('/USERS/%s/controllers/%s [PUT] =>Changing user access, check set_controller_access.log for more information!', user, controller)
                code, response = 202, 'Process being handled'
            else:
                code, response = errors.no_permission()
                LOGGER.error('/USERS/%s/controllers/%s [PUT] => No Permission to perform this action', user, controller)
        else:
            code, response = errors.does_not_exist('user')
            LOGGER.error('/USERS/%s/controllers/%s [PUT] => User %s does not exist', user, controller, user)
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
        con = execute_task(juju.authorize, token, juju.check_input(controller))
        LOGGER.info('/USERS/%s/controllers/%s/models [GET] => Authorized!', user, controller)
        if execute_task(juju.user_exists, user):
            if token.is_admin or token.username == user:
                code, response = 200, execute_task(juju.get_models_access, con, user)
                LOGGER.info('/USERS/%s/controllers/%s/models [GET] => Succesfully retrieved models access!', user, controller)
            else:
                code, response = errors.no_permission()
                LOGGER.error('/USERS/%s/controllers/%s/models [GET] => No Permission to perform this action!', user, controller)
        else:
            code, response = errors.does_not_exist('user')
            LOGGER.error('/USERS/%s/controllers/%s/models [GET] => User %s does not exist!', user, controller, user)
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
        con = execute_task(juju.authorize, token, juju.check_input(controller))
        LOGGER.info('/USERS/%s/controllers/%s/models [PUT] => Authorized!', user, controller)
        if (token.is_admin or con.c_access == 'superuser') and user != 'admin':
            if execute_task(juju.user_exists, user):
                execute_task(juju.set_models_access, token, con, user, data)
                LOGGER.info('/USERS/%s/controllers/%s/models [PUT] => Setting model access, check set_model_access.log for more information!', user, controller)
                code, response = 202, 'Process being handled'
            else:
                code, response = errors.does_not_exist('user')
                LOGGER.error('/USERS/%s/controllers/%s/models [PUT] => User %s does not exist!', user, controller, user)
        else:
            user_access = execute_task(juju.get_models_access, con, user)
            if execute_task(juju.user_exists, user):
                for mod in data:
                    if not mod['name'] in user_access:
                        LOGGER.error('/USERS/%s/controllers/%s/models [PUT] => No Permission to perform this action!', user, controller)
                        return juju.create_response(errors.no_permission())
                execute_task(juju.set_models_access, token, con, user, data)
                LOGGER.info('/USERS/%s/controllers/%s/models [PUT] => Setting model access, check set_model_access.log for more information!', user, controller)
                code, response = 202, 'Process being handled'
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
        con, mod = execute_task(juju.authorize, token, juju.check_input(controller), juju.check_input(model))
        LOGGER.info('/USERS/%s/controllers/%s/models/%s [GET] => Authorized!', user, controller, model)
        if execute_task(juju.user_exists, user):
            if token.is_admin or token.username == user:
                access = execute_task(juju.get_model_access, mod.m_name, con.c_name, user)
                code, response = 200, {'access' : access}
                LOGGER.info('/USERS/%s/controllers/%s/models/%s [GET] => Succesfully retrieved model access!', user, controller, model)
            else:
                code, response = errors.no_permission()
                LOGGER.error('/USERS/%s/controllers/%s/models/%s [GET] => No Permission to perform this action!', user, controller, model)
        else:
            code, response = errors.does_not_exist('user')
            LOGGER.error('/USERS/%s/controllers/%s/models/%s [GET] => User %s does not exist!', user, controller, model, user)
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
