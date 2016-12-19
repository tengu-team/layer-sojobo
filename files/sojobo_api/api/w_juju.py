# !/usr/bin/env python3
# Copyright (C) 2016  Qrama
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
# pylint: disable=c0111,c0301,c0325,c0103,r0204,r0913,r0902

import base64
import hashlib
from importlib import import_module
import json
import os
from subprocess import check_call, check_output, STDOUT, CalledProcessError
import requests
# import tempfile
import yaml
from sojobo_api import get_api_dir
from flask import abort


def get_user():
    return os.environ.get('JUJU_ADMIN_USER')
    # return 'tengu-ui'


def get_password():
    return os.environ.get('JUJU_ADMIN_PASSWORD')
    # return '4vQwtSKMNTyRtTfU'


def get_charm_dir():
    return os.environ.get('LOCAL_CHARM_DIR')
    # return '/tmp'


def get_controller_types():
    c_list = {}
    for f_path in os.listdir('{}/api'.format(get_api_dir())):
        if 'controller_' in f_path and '.pyc' not in f_path:
            name = f_path.split('.')[0]
            c_list[name.split('_')[1]] = import_module('api.{}'.format(name))
    return c_list


def app_supports_series(app_name, series):
    if 'local:' in app_name:
        with open('{}/{}/metadata.yaml'.format(get_charm_dir(), app_name.split(':')[1])) as data:
            supports = series in yaml.load(data)['series']
    else:
        supports = False
        data = requests.get('https://api.jujucharms.com/v4/{}/expand-id'.format(app_name))
        for value in json.loads(data.text):
            if series in value['Id']:
                supports = True
                break
    return supports


def cloud_supports_series(token, series):
    return series in get_controller_types()[token.c_token.type].get_supported_series()


def parse_c_access(access):
    if access in ['login', 'add-model', 'superuser']:
        return access
    else:
        return 'login'


def parse_m_access(access):
    if access in ['read', 'write', 'admin']:
        return access
    else:
        return 'read'


def login(controller, user=get_user(), password=get_password()):
    with open(os.devnull, 'w') as FNULL:
        check_call(['juju', 'logout'], stdout=FNULL, stderr=FNULL)
        check_output(['juju', 'login', user, '--controller', controller], input=password + '\n', universal_newlines=True, stderr=FNULL)
        check_call(['juju', 'switch', controller], stdout=FNULL, stderr=FNULL)


def output_pass(commands, password=get_password()):
    with open(os.devnull, 'w') as FNULL:
        return check_output(commands, input=password + '\n', universal_newlines=True, stderr=FNULL)


class JuJu_Token(object):
    def __init__(self, auth):
        self.username = auth.username
        self.password = auth.password
        self.is_admin = self.set_admin()
        self.c_name = None
        self.c_access = None
        self.c_token = None
        self.m_name = None
        self.m_access = None

    def set_controller(self, c_name, c_access, c_token):
        self.c_name = c_name
        self.c_access = parse_c_access(c_access)
        self.c_token = c_token

    def set_model(self, modelname, modelaccess):
        self.m_name = modelname
        self.m_access = parse_m_access(modelaccess)

    def m_shared_name(self):
        return "{}/{}".format(get_user(), self.m_name)

    def get_credentials(self):
        return {'credentials': {self.c_name: {self.username: self.c_token.get_credentials()}}}

    def get_cloud(self):
        return {'clouds':{self.c_name: self.c_token.get_cloud()}}

    def set_admin(self):
        return self.username in get_admins()


def authenticate(api_key, auth, controller=None, modelname=None):
    with open('{}/api-key'.format(get_api_dir()), 'r') as key:
        apikey = key.readlines()[0]
    if api_key != apikey:
        abort(403, {'message': 'You do not have permission to perform this operation!'})
    token = JuJu_Token(auth)
    if controller is None:
        return token
    else:
        c_access = get_controller_access(token, controller)
        if c_access is None:
            abort(403, {'message': 'This controller does not exist or you do not have permission to see it!'})
        c_type, c_endpoint = get_controller_info(controller)
        c_token = getattr(get_controller_types()[c_type], 'Token')(c_endpoint, auth)
        token.set_controller(controller, c_access, c_token)
        if modelname:
            models_info = json.loads(check_output(['juju', 'models', '--format', 'json']).decode('utf-8'))
            if '{}/{}'.format(get_user(), modelname) in models_info.values():
                token.set_model(modelname, models_info[0]['models']['users'][token.username]['access'])
            else:
                abort(403, {'message': 'This model does not exist or you do not have permission to see it!'})
        return token
###############################################################################
# CONTROLLER FUNCTIONS
###############################################################################
def create_controller(token, c_type, name, region, credentials, cfile=None):
    exists = False
    for key, value in get_controller_types().items():
        if c_type == key:
            output = value.create_controller(name, region, credentials, cfile)
            print(output)
            add_superuser(token, name)
            exists = True
            break
    if not exists:
        output = 'Incorrect controller type. Supported options are: {}'.format(get_controller_types().keys())
    return output


def delete_controller(token):
    login(token.c_name)
    return output_pass(['juju', 'destroy-controller', token.c_name, '-y'])


def get_all_controllers():
    controllers = json.loads(output_pass(['juju', 'controllers', '--format', 'json']))
    return controllers['controllers'].keys()


def get_controller_access(token, controller):
    try:
        login(controller, token.username, token.password)
        controllers_info = json.loads(output_pass(['juju', 'controllers', '--format', 'json'], token.password))
        access = controllers_info['controllers'][controller]['access']
    except CalledProcessError:
        access = None
    return access


def get_controller_info(controller):
    with open('/home/ubuntu/.local/share/juju/clouds.yaml', 'r') as y_clouds:
        clouds = yaml.load(y_clouds)
    return clouds['clouds'][controller]['type'], clouds['clouds'][controller]['endpoint']


def get_controllers(token):
    result = {}
    for controller in get_all_controllers():
        access = get_controller_access(token, controller)
        if access is not None:
            result[controller] = access
    return result
###############################################################################
# MODEL FUNCTIONS
###############################################################################
def model_exists(token, model):
    login(token.c_name)
    data = json.loads(output_pass(['juju', 'list-models', '--format', 'json']))
    return model in data.values()


def get_all_models(controller):
    login(controller)
    data = json.loads(output_pass(['juju', 'list-models', '--format', 'json']))
    models = []
    for model in data['models']:
        models.append(model['name'])
    return models


def get_models(token):
    models = {}
    for model in get_all_models(token.c_name):
        access = get_model_access(token, model)
        if access is not None:
            models[model] = access
    return models


def get_model_access(token, model):
    login(token.c_name)
    data = json.loads(output_pass(['juju', 'users', model, '--format', 'json']))
    try:
        access = data[token.username]['access']
    except KeyError:
        access = None
    return access


def get_gui_url(token):
    login(token.c_name)
    return check_output(['juju', 'gui', '--no-browser', '--model', token.m_name],
                        universal_newlines=True, stderr=STDOUT).rstrip()


def create_model(token, model, ssh_key=None):
    # credentials = token.get_credentials()
    # tmp = tempfile.NamedTemporaryFile(mode="w+", delete=False)
    # tmp.write(json.dumps(credentials))
    # tmp.close()  # deletes the file
    # check_call(['juju', 'add-credential', '--replace', token.c_name, '-f', tmp.name])
    login(token.c_name)
    output = {}
    output['add-model'] = output_pass(['juju', 'add-model', model, '--credential', get_user()]) # token.username])
    output['grant'] = output_pass(['juju', 'grant', token.username, 'admin', model])
    if ssh_key is not None:
        output['ssh'] = add_ssh_key(token, ssh_key)
    return output


def delete_model(token):
    login(token.c_name)
    return output_pass(['juju', 'destroy-model', '-y', token.m_name])


def add_ssh_key(token, ssh_key):
    login(token.c_name)
    return output_pass(['juju', 'add-ssh-key', '-m', token.m_name, '"{}"'.format(ssh_key)])


def remove_ssh_key(token, ssh_key):
    login(token.c_name)
    key = base64.b64decode(bytes(ssh_key.strip().split()[1].encode('ascii')))
    fp_plain = hashlib.md5(key).hexdigest()
    fingerprint = ':'.join(a+b for a, b in zip(fp_plain[::2], fp_plain[1::2]))
    return output_pass(['juju', 'remove-ssh-key', '-m', token.m_name, fingerprint])


def model_status(token):
    login(token.c_name)
    general = output_pass(['juju', 'show-model', '-m', token.m_name, '--format', 'json'])
    detail = output_pass(['juju', 'status', '-m', token.m_name, '--format', 'json'])
    return json.loads({'general': general, 'detail': detail})
###############################################################################
# USER FUNCTIONS
###############################################################################
def create_user(username, password):
    for controller in get_all_controllers():
        check_call(['juju', 'add-user', '-c', controller, username])
        check_call(['juju', 'grant', '-c', controller, username, 'login'])
        check_call(['juju', 'disable-user', '-c', controller, username])
    change_password(username, password)
    return 'The user {} has been created'.format(username)


def delete_user(username):
    for controller in get_all_controllers():
        for model in get_all_models(controller):
            check_call(['juju', 'revoke', username, 'read', model, '-c', controller])
        check_call(['juju', 'disable-user', '-c', controller, username])
    return 'The user {} has been disabled'.format(username)


def change_password(username, password):
    for controller in get_all_controllers():
        check_output(['juju', 'change-user-password', '-c', controller, username],
                     input="{}\n{}".format(password, password))
    return '{} password has been changed'.format(username)


def get_users(controller):
    if controller is None:
        result = None
    else:
        login(controller)
        users = json.loads(output_pass(['juju', 'list-users', '--format', 'json']))
        result = {u['user-name']: u['access'] for u in users}
    return result


def get_admins():
    result = set()
    not_first = False
    for controller in get_all_controllers():
        users = get_users(controller)
        for model in get_all_models(controller):
            data = json.loads(output_pass(['juju', 'users', model, '--format', 'json']))
            temp = set()
            for key, value in data.items():
                if value['access'] == 'admin' and users[key] == 'superuser':
                    temp.add(key)
            if not_first:
                result = result.intersection(temp)
            else:
                result = temp
                not_first = True
    return list(result)


def make_admin(username):
    for controller in get_all_controllers():
        login(controller)
        check_call(['juju', 'grant', username, 'superuser'])
        for model in get_all_models(controller):
            check_call(['juju', 'grant', username, 'admin', model])
    return '{} has been made an admin'.format(username)


def add_superuser(username, controller):
    login(controller)
    return output_pass(['juju', 'grant', username, 'superuser'])


def add_to_controller(token, username, access):
    login(token.c_name)
    check_call(['juju', 'enable-user', username])
    return output_pass(['juju', 'grant', username, parse_c_access(access)])


def remove_from_controller(token, username):
    login(token.c_name)
    return output_pass(['juju', 'disable-user', username])


def add_to_model(token, username, access):
    login(token.c_name)
    check_call(['juju', 'enable-user', username])
    return output_pass(['juju', 'grant', username, access, token.m_name])


def remove_from_model(token, username):
    login(token.c_name)
    return output_pass(['juju', 'revoke', username, token.m_name])


def user_exists(username):
    return username in json.loads(output_pass(['juju', 'users', '--format', 'json'])[1:-2]).values()
#####################################################################################
# APPLICATION FUNCTIONS
#####################################################################################
def config(token, app_name):
    login(token.c_name)
    return json.loads(output_pass(['juju', 'config', app_name, '--model', token.modelname, '--format', 'json']))


def app_exists(token, app_name):
    login(token.c_name)
    data = json.loads(output_pass(['juju', 'status', '-c', token.c_name, '-m', token.m_name]))
    return app_name in data['applications'].keys()


def deploy_app(token, app_name, series=None, target=None):
    if not token.c_token.supportlxd and 'lxd' in target:
        return '{} doesn\'t support lxd-containers'.format(token.c_token.c_type.upper())
    else:
        if 'local:' in app_name:
            app_name = app_name.replace('local:', '{}/'.format(get_charm_dir()))
        login(token.c_name)
        return output_pass(['juju', 'deploy', app_name, '-m', token.m_name, '--series', series, '--to', target])


def remove_app(token, app_name):
    login(token.c_name)
    return output_pass(['juju', 'remove-application', '-m', token.m_name, app_name])


def add_machine(token, series=None):
    login(token.c_name)
    return output_pass(['juju', 'add-machine', '-m', token.m_name, '--series', series])


def machine_exists(token, machine):
    login(token.c_name)
    data = json.loads(output_pass(['juju', 'status', '-m', token.m_name, '--format', 'json']))
    if 'lxd' in machine:
        return machine in data['machines'][machine.split('/')[0]]['containers'].keys()
    else:
        return machine in data['machines'].keys()


def get_machine_series(token, machine):
    login(token.c_name)
    data = json.loads(output_pass(['juju', 'list-machines' '-m', token.m_name, '--format', 'json']))
    if 'lxd' in machine:
        return data['machines'][machine.split('/')[0]]['containers'][machine]['series']
    else:
        return data['machines'][machine]['series']


def remove_machine(token, machine):
    login(token.c_name)
    return output_pass(['juju', 'remove-machine', '--force', token.m_name, machine])


def unit_exists(token, unit):
    login(token.c_name)
    data = json.loads(output_pass(['juju', 'status', '-m', token.m_name, '--format', 'json']))
    return unit in data['units'].keys()


def add_unit(token, app_name, target=None):
    login(token.c_name)
    return output_pass(['juju', 'add-unit', app_name, '-m', token.m_name, '--to', target])


def remove_unit(token, unit_name):
    login(token.c_name)
    return output_pass(['juju', 'remove-unit', '-m', token.m_name, unit_name])


def add_relation(token, app1, app2):
    login(token.c_name)
    return output_pass(['juju', 'add-relation', '-m', token.m_name, app1, app2])


def remove_relation(token, app1, app2):
    login(token.c_name)
    return output_pass(['juju', 'remove-relation', '-m', token.m_name, app1, app2])


def get_app_info(token, app_name):
    login(token.c_name)
    return json.loads(output_pass(['juju', 'status', '-m', token.m_name]))['applications'][app_name]
