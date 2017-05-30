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
import subprocess
from flask import request, Blueprint

from sojobo_api import settings
from sojobo_api.api import w_errors as errors, w_juju as juju, w_mongo as mongo
from sojobo_api.api.w_juju import execute_task, Controller_Connection

USERS = Blueprint('users', __name__)
def get():
    return USERS


@USERS.route('/', methods=['GET'])
def get_users_info():
    #try:
    token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
    u_info = mongo.get_user(token.username)
    access_list = []
    if token.is_admin:
        code, response = 200, execute_task(juju.get_users_info)
    else:
        for controller in u_info['access']:
            c_name = list(controller.keys())[0]
            if u_info[c_name]['access'] == 'superuser':
                c_users = mongo.get_controller_users(controller)
                for usr in c_users:
                    access_list.append(execute_task(get_user_info, usr['name']))
        if access_list:
            response_list = []
            for ac in access_list:
                if ac not in response_list:
                    response_list.append(ac)
            code, response = 200, response_list
        else:
            access_list.append(execute_task(get_user_info, token.username))
            code, response = 200, access_list
    # except KeyError:
    #     code, response = errors.invalid_data()
    return juju.create_response(code, response)


@USERS.route('/', methods=['PUT'])
def reactivate_user():
    data = request.json
    try:
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        user = juju.check_input(data['username'])
        if token.is_admin:
            if execute_task(juju.user_exists, user):
                controllers = execute_task(juju.get_all_controllers)
                for con in controllers:
                    controller = Controller_Connection()
                    execute_task(controller.set_controller, token, con)
                    execute_task(juju.enable_user, controller, user)
                    execute_task(controller.disconnect)
                mongo.enable_user(user)
                code, response = 200, 'User {} succesfully activated'.format(user)
        else:
            code, response = errors.unauthorized()
    except KeyError:
        code, response = errors.invalid_data()
    return juju.create_response(code, response)

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
                mongo.create_user(user)
                controllers = execute_task(juju.get_all_controllers)
                for con in controllers:
                    controller = Controller_Connection()
                    execute_task(controller.set_controller, token, con)
                    execute_task(juju.create_user, controller, user, data['password'])
                    execute_task(controller.disconnect)
                code, response = 200, 'User {} succesfully created'.format(user)
        else:
            code, response = errors.unauthorized()
    except KeyError:
        code, response = errors.invalid_data()
    return juju.create_response(code, response)


@USERS.route('/<user>', methods=['GET'])
def get_user_info(user):
    try:
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        usr = juju.check_input(user)
        if execute_task(juju.user_exists, usr):
            if usr == token.username or token.is_admin:
                code, response = 200, execute_task(juju.get_user_info, usr)
            else:
                code, response = errors.unauthorized()
        else:
            code, response = errors.does_not_exist('user')
    except KeyError:
        code, response = errors.invalid_data()
    return juju.create_response(code, response)



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
                code, response = errors.unauthorized()
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
                    mongo.disable_user(usr)
                else:
                    code, response = 403, 'This would remove the admin from the system!'
            else:
                code, response = errors.does_not_exist('user')
        else:
            code, response = errors.unauthorized()
    except KeyError:
        code, response = errors.invalid_data()
    return juju.create_response(code, response)


@USERS.route('/<user>/ssh', methods=['GET'])
def get_ssh_keys(user):
    try:
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        if token.is_admin or token.username == user:
            print(mongo.get_ssh_keys(user))
            code, response = 200, mongo.get_ssh_keys(user)
    except KeyError:
        code, response = errors.invalid_data()
    return juju.create_response(code, response)


@USERS.route('/<user>/ssh', methods=['POST'])
def add_ssh_key(user):
    data = request.json
    try:
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        cons = mongo.get_all_controllers()
        usr = juju.check_input(user)
        for con in cons:
            if mongo.get_controller_access(con, token.username) == 'superuser':
                subprocess.Popen(["python3", "{}/scripts/add_ssh_keys.py".format(juju.get_api_dir()), token.username,
                                  token.password, juju.get_api_dir(), con, data['ssh-key'], settings.MONGO_URI, usr])
        code, response = 202, 'Process being handeled'
    except KeyError:
        code, response = errors.invalid_data()
    return juju.create_response(code, response)


@USERS.route('/<user>/ssh', methods=['DELETE'])
def delete_ssh_key(user):
    data = request.json
    try:
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        cons = mongo.get_all_controllers()
        usr = juju.check_input(user)
        for con in cons:
            if mongo.get_controller_access(con, token.username) == 'superuser':
                subprocess.Popen(["python3", "{}/scripts/remove_ssh_keys.py".format(juju.get_api_dir()), token.username,
                                  token.password, juju.get_api_dir(), con, data['ssh-key'], settings.MONGO_URI, usr])
        code, response = 202, 'Process being handeled'
    except KeyError:
        code, response = errors.invalid_data()
    return juju.create_response(code, response)

@USERS.route('/<user>/controllers', methods=['GET'])
def get_controllers_access(user):
    try:
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        usr = juju.check_input(user)
        if execute_task(juju.user_exists, usr):
            if token.is_admin or token.username == usr:
                code, response = 200, execute_task(juju.get_controllers_access, usr)
            else:
                code, response = errors.unauthorized()
        else:
            code, response = errors.does_not_exist('user')
    except KeyError:
        code, response = errors.invalid_data()
    return juju.create_response(code, response)


@USERS.route('/<user>/controllers/<controller>', methods=['GET'])
def get_ucontroller_access(user, controller):
    # try:
    token, con = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, juju.check_input(controller))
    usr = juju.check_input(user)
    if execute_task(juju.user_exists, usr):
        if token.is_admin or token.username == usr:
            code, response = 200, execute_task(juju.get_ucontroller_access, con, usr)
        else:
            code, response = errors.unauthorized()
    else:
        code, response = errors.does_not_exist('user')
    execute_task(con.disconnect)
    # except KeyError:
    #     code, response = errors.invalid_data()
    return juju.create_response(code, response)


@USERS.route('/<user>/controllers/<controller>', methods=['PUT'])
def grant_to_controller(user, controller):
    try:
        access = juju.check_access(request.json['access'])
        usr = juju.check_input(user)
        token, con = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, juju.check_input(controller))
        u_exists = execute_task(juju.user_exists, usr)
        if u_exists:
            if execute_task(juju.check_same_access, usr, access, con):
                code, response = 409, "Access level already set to {}".format(access)
                execute_task(con.disconnect)
            else:
                execute_task(con.disconnect)
                subprocess.Popen(["python3", "{}/scripts/set_user_access.py".format(juju.get_api_dir()), token.username,
                              token.password, juju.get_api_dir(),settings.MONGO_URI, usr, access, controller])
                code, response = 202, 'Process being handeled'
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
        if execute_task(juju.user_exists, usr):
            if con.c_access == 'superuser' and user != 'admin':
                execute_task(juju.controller_revoke, con, usr)
                mongo.set_controller_access(con.c_name, usr, 'login')
                mongo.remove_models_access(con.c_name, usr)
                code, response = 200, execute_task(juju.get_controller_access, con, usr)
            else:
                code, response = errors.unauthorized()
        else:
            code, response = errors.does_not_exist('user')
        execute_task(con.disconnect)
    except KeyError:
        code, response = errors.invalid_data()
    return juju.create_response(code, response)


@USERS.route('/<user>/controllers/<controller>/models', methods=['GET'])
def get_models_access(user, controller):
    try:
        token, con = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, juju.check_input(controller))
        usr = juju.check_input(user)
        if execute_task(juju.user_exists, usr):
            if token.is_admin or token.username == usr:
                code, response = 200, execute_task(juju.get_models_access, con, usr)
            else:
                code, response = errors.unauthorized()
        else:
            code, response = errors.does_not_exist('user')
        execute_task(con.disconnect)
    except KeyError:
        code, response = errors. invalid_data()
    return juju.create_response(code, response)


@USERS.route('/<user>/controllers/<controller>/models/<model>', methods=['GET'])
def get_model_access(user, controller, model):
    try:
        token, con, mod = execute_task(juju.authenticate, request.headers['api-key'], request.authorization,
                                       juju.check_input(controller), juju.check_input(model))
        usr = juju.check_input(user)
        if execute_task(juju.user_exists, usr):
            if token.is_admin or token.username == usr:
                access = execute_task(juju.get_model_access, mod.m_name, con.c_name, usr)
                code, response = 200, {'access' : access}
            else:
                code, response = errors.unauthorized()
        else:
            code, response = errors.does_not_exist('user')
        execute_task(mod.disconnect)
        execute_task(con.disconnect)
    except KeyError:
        code, response = errors.invalid_data()
    return juju.create_response(code, response)


@USERS.route('/<user>/controllers/<controller>/models/<model>', methods=['PUT'])
def grant_to_model(user, controller, model):
    try:
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        access = juju.check_access(request.json['access'])
        usr = juju.check_input(user)
        mod_access = mongo.get_model_access(controller, model, usr)
        con_access = mongo.get_controller_access(controller, usr)
        u_exists = execute_task(juju.user_exists, user)
        if u_exists:
            if (mod_access == 'admin' or con_access == 'superuser') and user != 'admin':
                subprocess.Popen(["python3", "{}/scripts/set_model_access.py".format(juju.get_api_dir()), token.username,
                              token.password, juju.get_api_dir(),settings.MONGO_URI, usr, access, controller, model])
                code, response = 202, 'Process being handeled'
            else:
                code, response =  errors.unauthorized()
        else:
            code, response = errors.does_not_exist('user')
    except KeyError:
        code, response = errors.invalid_data()
    return juju.create_response(code, response)


@USERS.route('/<user>/controllers/<controller>/models/<model>', methods=['DELETE'])
def revoke_from_model(user, controller, model):
    try:
        token, con, mod = execute_task(juju.authenticate, request.headers['api-key'], request.authorization,
                                       juju.check_input(controller), juju.check_input(model))
        usr = juju.check_input(user)
        if execute_task(juju.user_exists, usr):
            if (mod.m_access == 'admin' or mod.c_access == 'superuser') and user != 'admin':
                execute_task(juju.model_revoke, mod, usr)
                mongo.remove_model(con.c_name, mod.m_name, usr)
                code, response = 200, 'Revoked access for user {} on model {}'.format(usr, model)
            else:
                code, response = errors.unauthorized()
        else:
            code, response = errors.does_not_exist('user')
        execute_task(con.disconnect)
        execute_task(mod.disconnect)
    except KeyError:
        code, response = errors.invalid_data()
    return juju.create_response(code, response)
