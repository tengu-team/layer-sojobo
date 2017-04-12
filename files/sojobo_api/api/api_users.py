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
# pylint: disable=c0111,c0301,c0325,c0326,w0406,e0401
###############################################################################
# USER FUNCTIONS
###############################################################################
from flask import request, Blueprint

from sojobo_api.api import w_errors as errors, w_juju as juju, w_mongo as mongo
from sojobo_api.api.w_juju import execute_task, Controller_Connection

USERS = Blueprint('users', __name__)
def get():
    return USERS


@USERS.route('/', methods=['GET'])
def get_users_info():
    try:
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        if token.is_admin:
            code, response = 200, juju.get_users_info()
        else:
            code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return code, response


@USERS.route('/', methods=['POST'])
def create_user():
    data = request.json
    try:
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        user = juju.check_input(data['username'])
        if token.is_admin:
            if execute_task(juju.user_exists, user):
                code, response = errors.already_exists('user')
            else:
                controllers = execute_task(juju.get_all_controllers)
                for con in controllers:
                    controller = Controller_Connection()
                    execute_task(controller.set_controller, token, con)
                    execute_task(juju.create_user, controller, user, data['password'])
                    execute_task(controller.disconnect)
                code, response = 200, 'User {} succesfully created'.format(user)
        else:
            code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return juju.create_response(code, response)


@USERS.route('/<user>', methods=['GET'])
def get_user_info(user):
    # try:
    #     token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
    #     usr = juju.check_input(user)
    #     if juju.user_exists(usr):
    #         if usr == token.username or token.is_admin:
    #             code, response = 200, juju.get_user_info(token, usr)
    #         else:
    #             code, response = errors.no_permission()
    #     else:
    #         code, response = errors.does_not_exist('user')
    # except KeyError:
    #     code, response = errors.invalid_data()
    return 501, 'Not Implemented'


@USERS.route('/<user>', methods=['PUT'])
def change_user_password(user):
    try:
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        usr = juju.check_input(user)
        if execute_task(juju.user_exists, usr):
            if usr == token.username or token.is_admin:
                controllers = execute_task(juju.get_all_controllers)
                for con in controllers:
                    controller = Controller_Connection()
                    execute_task(controller.set_controller, token, con)
                    execute_task(juju.change_user_password, controller, usr, request.json['password'])
                    execute_task(controller.disconnect)
                code, response = 200, 'succesfully changed password for user {}'.format(usr)
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.does_not_exist('user')
    except KeyError:
        code, response = errors.invalid_data()
    return juju.create_response(code, response)


@USERS.route('/<user>', methods=['DELETE'])
def delete_user(user):
    try:
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        usr = juju.check_input(user)
        if token.is_admin:
            if execute_task(juju.user_exists, usr):
                if usr != 'admin':
                    controllers = execute_task(juju.get_all_controllers)
                    for con in controllers:
                        controller = Controller_Connection()
                        execute_task(controller.set_controller, token, con)
                        execute_task(juju.delete_user, controller, usr)
                        execute_task(controller.disconnect)
                    code, response = 200, 'User {} succesfully removed'.format(usr)
                else:
                    code, response = 403, 'This would remove the admin from the system!'
            else:
                code, response = errors.does_not_exist('user')
        else:
            code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return juju.create_response(code, response)


@USERS.route('/<user>/controllers', methods=['GET'])
def get_controllers_access(user):
    # try:
    #     token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
    #     usr = juju.check_input(user)
    #     if juju.user_exists(usr):
    #         if token.is_admin or token.username == usr:
    #             code, response = 200, juju.get_controllers_access(token, usr)
    #         else:
    #             code, response = errors.no_permission()
    #     else:
    #         code, response = errors.does_not_exist('user')
    # except KeyError:
    #     code, response = errors.invalid_data()
    return 501, 'Not Implemented'


@USERS.route('/<user>/controllers/<controller>', methods=['GET'])
def get_ucontroller_access(user, controller):
    # try:
    #     token, con = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, juju.check_input(controller))
    #     usr = juju.check_input(user)
    #     if juju.user_exists(usr):
    #         if token.is_admin or token.username == usr:
    #             code, response = 200, juju.get_ucontroller_access(token, usr)
    #         else:
    #             code, response = errors.no_permission()
    #     else:
    #         code, response = errors.does_not_exist('user')
    # except KeyError:
    #     code, response = errors.invalid_data()
    return 501, 'Not Implemented'


@USERS.route('/<user>/controllers/<controller>', methods=['PUT'])
def grant_to_controller(user, controller):
    try:
        token, con = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, juju.check_input(controller))
        access = juju.check_access(request.json['access'])
        usr = juju.check_input(user)
        u_exists = execute_task(juju.user_exists, usr)
        if u_exists:
            if token.c_access == 'superuser' and user != 'admin':
                execute_task(juju.controller_grant, con, usr, access)
                code, response = 200, execute_task(juju.get_controller_access, token, usr)
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.does_not_exist('user')
    except KeyError:
        code, response = errors.invalid_data()
    return juju.create_response(code, response)


@USERS.route('/<user>/controllers/<controller>', methods=['DELETE'])
def revoke_from_controller(user, controller):
    try:
        token, con = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, juju.check_input(controller))
        usr = juju.check_input(user)
        if juju.user_exists(usr):
            if con.c_access == 'superuser' and user != 'admin':
                execute_task(juju.controller_revoke, con, usr)
                code, response = 200, execute_task(juju.get_controller_access, token, usr)
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.does_not_exist('user')
    except KeyError:
        code, response = errors.invalid_data()
    return juju.create_response(code, response)


@USERS.route('<user>/controllers/<controller>/models', methods=['GET'])
def get_models_access(user, controller):
    # try:
    #     token, con = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, juju.check_input(controller))
    #     usr = juju.check_input(user)
    #     if juju.user_exists(usr):
    #         if token.is_admin or token.username == usr:
    #             code, response = 200, juju.get_models_access(token, usr)
    #         else:
    #             code, response = errors.no_permission()
    #     else:
    #         code, response = errors.does_not_exist('user')
    # except KeyError:
    #     code, response = errors. invalid_data()
    return 501, 'Not Implemented'


@USERS.route('/<user>/controllers/<controller>/models/<model>', methods=['GET'])
def get_model_access(user, controller, model):
    # try:
    #     token, con, mod = execute_task(juju.authenticate, request.headers['api-key'], request.authorization,
    #                                    juju.check_input(controller), juju.check_input(model))
    #     usr = juju.check_input(user)
    #     if juju.user_exists(usr):
    #         if token.is_admin or token.username == usr:
    #             code, response = 200, juju.get_umodel_access(token, usr)
    #         else:
    #             code, response = errors.no_permission()
    #     else:
    #         code, response = errors.does_not_exist('user')
    # except KeyError:
    #     code, response = errors.invalid_data()
    return 501, 'Not Implemented'


@USERS.route('/<user>/controllers/<controller>/models/<model>', methods=['PUT'])
def grant_to_model(user, controller, model):
    try:
        token, con, mod = execute_task(juju.authenticate, request.headers['api-key'], request.authorization,
                                       juju.check_input(controller), juju.check_input(model))
        access = juju.check_access(request.json['access'])
        usr = juju.check_input(user)
        u_exists = juju.user_exists(user)
        if u_exists:
            if (mod.m_access == 'admin' or mod.c_access == 'superuser') and user != 'admin':
                execute_task(juju.model_grant, mod, usr, access)
                code, response = 200, 'Granted access for user {} on model {}'.format(usr, model)
            else:
                code, response =  errors.no_permission()
        else:
            code, response = errors.does_not_exist('user')
        execute_task(con.disconnect)
        execute_task(mod.disconnect)
    except KeyError:
        code, response = errors.invalid_data()
    return juju.create_response(code, response)


@USERS.route('/<user>/controllers/<controller>/models/<model>', methods=['DELETE'])
def revoke_from_model(user, controller, model):
    try:
        token, con, mod = execute_task(juju.authenticate, request.headers['api-key'], request.authorization,
                                       juju.check_input(controller), juju.check_input(model))
        usr = juju.check_input(user)
        if juju.user_exists(usr):
            if (mod.m_access == 'admin' or mod.c_access == 'superuser') and user != 'admin':
                execute_task(juju.model_revoke, model, usr)
                code, response = 200, 'Revoked access for user {} on model {}'.format(usr, model)
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.does_not_exist('user')
        execute_task(con.disconnect)
        execute_task(mod.disconnect)
    except KeyError:
        code, response = errors.invalid_data()
    return juju.create_response(code, response)
