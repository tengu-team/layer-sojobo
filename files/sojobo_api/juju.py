
# Copyright (C) 2016  Ghent University
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
# !/usr/bin/env python3
import base64
import hashlib
from importlib import import_module
import json
import os
from subprocess import check_call, check_output, STDOUT, CalledProcessError
# import tempfile
import yaml

import helpers
from flask import abort


USER = os.environ.get('JUJU_ADMIN_USER')
PASSWORD = os.environ.get('JUJU_ADMIN_PASSWORD')


def get_controller_types():
    path = '{}/juju_controllers'.format(helpers.get_api_dir())
    files = [f.split('.'[0]) for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
    files.remove('__init__')
    result = {}
    for c_file in files:
        result[c_file] = import_module('juju_controllers.{}'.format(c_file))
    return result


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
        return "{}/{}".format(USER, self.m_name)

    def get_credentials(self):
        return {'credentials': {self.c_name: {self.username: self.c_token.get_credentials()}}}

    def get_cloud(self):
        return {'clouds':{self.c_name: self.c_token.get_cloud()}}

    def set_admin(self):
        admin = True
        for controller in get_all_controllers():
            if get_controller_access(self.username, self.password, controller) != 'superuser':
                admin = False
                break
        self.admin = admin


def authenticate(api_key, auth, controller=None, modelname=None):
    helpers.check_api_key(api_key)
    token = JuJu_Token(auth)
    if controller is None:
        return token
    else:
        c_access = get_controller_access(token.username, token.password, controller)
        if c_access is None:
            abort(403, {'message': 'This controller does not exist or you do not have permission to see it!'})
        c_type, c_endpoint = get_controller_info(controller)
        for key, value in get_controller_types().items():
            if c_type == key:
                c_token = value.Token(c_endpoint, auth)
        token.set_controller(controller, c_access, c_token)
        if modelname:
            models_info = json.loads(check_output(['juju', 'models', '--format', 'json']))
            if '{}/{}'.format(USER, modelname) in models_info.values():
                token.set_model(modelname, models_info[0]['models']['users'][token.username]['access'])
            else:
                abort(403, {'message': 'This model does not exist or you do not have permission to see it!'})
        check_call(['juju', 'logout'])
        check_output(['juju', 'login', USER, '--controller', token.c_name], input=PASSWORD + '\n',
                     universal_newlines=True)
        return token
###############################################################################
# CONTROLLER FUNCTIONS
###############################################################################
def create_controller(token, c_type, name, region, credentials):
    exists = False
    for key, value in get_controller_types().items():
        if c_type == key:
            output = value.create_controller(name, region, credentials)
            add_superuser(token, name)
            exists = True
            break
    if not exists:
        output = 'Incorrect controller type. Supported options are: {}'.format(get_controller_types().keys())
    return output


def delete_controller(token):
    return check_call(['juju', 'destroy-controller', '--destroy-all-models', token.c_name, '-y'])


def get_all_controllers():
    controllers = json.loads(check_output(['juju', 'controllers', '--format', 'json']))
    return controllers['controllers'].keys()


def get_controller_access(username, password, controller):
    try:
        check_output(['juju', 'login', username, '--controller', controller], input=password + '\n',
                     universal_newlines=True)
        controllers_info = json.loads(check_output(['juju', 'controllers', '--format', 'json']))
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
        access = get_controller_access(token.username, token.password, controller)
        if access is not None:
            result[controller] = access
    return result
###############################################################################
# MODEL FUNCTIONS
###############################################################################
def model_exists(token, model):
    data = json.loads(check_output(['juju', 'list-models', '--format', 'json', '-c', token.c_name]))
    return model in data.values()


def get_all_models(controller):
    data = json.loads(check_output(['juju', 'list-models', '--format', 'json', '-c', controller]))
    models = []
    for model in data['models']:
        models.append(model['name'])
    return models


def get_gui_url(token):
    return check_output(['juju', 'gui', '--no-browser', '--model', token.m_name],
                        universal_newlines=True, stderr=STDOUT).rstrip()


def create_model(token, model, ssh_key=None):
    # credentials = token.get_credentials()
    # tmp = tempfile.NamedTemporaryFile(mode="w+", delete=False)
    # tmp.write(json.dumps(credentials))
    # tmp.close()  # deletes the file
    # check_call(['juju', 'add-credential', '--replace', token.c_name, '-f', tmp.name])
    check_call(['juju', 'add-model', model, '--credential', USER]) # token.username])
    check_call(['juju', 'grant', token.username, 'admin', model])
    if ssh_key is not None:
        add_ssh_key(token, ssh_key)


def delete_model(token):
    check_call(['juju', 'destroy-model', '-y', token.m_name])


def add_ssh_key(token, ssh_key):
    check_call(['juju', 'add-ssh-key', '-m', token.m_name, '"{}"'.format(ssh_key)])


def remove_ssh_key(token, ssh_key):
    key = base64.b64decode(bytes(ssh_key.strip().split()[1].encode('ascii')))
    fp_plain = hashlib.md5(key).hexdigest()
    fingerprint = ':'.join(a+b for a, b in zip(fp_plain[::2], fp_plain[1::2]))
    check_call(['juju', 'remove-ssh-key', '-m', token.m_name, fingerprint])


def model_status(token):
    general = check_output(['juju', 'show-model', '-m', token.m_name, '--format', 'json'])
    detail = check_output(['juju', 'status', '-m', token.m_name, '--format', 'json'])
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


def change_password(username, password):
    for controller in get_all_controllers():
        check_output(['juju', 'change-user-password', '-c', controller, username],
                     input="{}\n{}".format(password, password))


def get_users(controller):
    users = json.loads(check_output(['juju', 'list-users', '-c', controller, '--format', 'json']))
    return {u['user-name']: u['access'] for u in users}


def get_admins():
    superadminusers = []
    for controller in get_all_controllers():
        users = get_users(controller)
        for model in get_all_models(controller):
            data = json.loads(check_output(['juju', 'users', '-c', controller, model, '--format', 'json']))
            temp = set()
            for key, value in data.items:
                if value['access'] == 'admin' and users[key] == 'superuser':
                    temp.add(key)
            superadminusers.append(temp)
    for i in range(0, len(superadminusers)-1):
        superadminusers[0] = superadminusers[0].intersection(superadminusers[i+1])
    return list(superadminusers[0])


def make_admin(username):
    for controller in get_all_controllers():
        check_call(['juju', 'grant', username, 'superuser', '-c', controller])
        for model in get_all_models(controller):
            check_call(['juju', 'grant', username, 'admin', model, '-c', controller])


def add_superuser(username, controller):
    return check_call(['juju', 'grant', username, 'superuser', '-c', controller])


def enable_user(username):
    for controller in get_all_controllers():
        check_call(['juju', 'enable-user', username, '-c', controller])


def add_to_controller(token, username, access):
    check_call(['juju', 'enable-user', username, '-c', token.c_name])
    check_call(['juju', 'grant', username, parse_c_access(access), '-c', token.c_name])


def remove_from_controller(token, username):
    check_call(['juju', 'disable-user', username, '-c', token.c_name])


def add_to_model(token, username, access):
    check_call(['juju', 'enable-user', username, '-c', token.c_name])
    check_call(['juju', 'grant', '-c', token.c_name, username, access, token.m_name])


def user_exists(username):
    exists = False
    output = check_output(['juju', 'users', '--format', 'json'])
    if username in json.loads(output[1:-2]).values():
        exists = True
    return exists
#####################################################################################
# To Check
#####################################################################################
def config(token, appname):
    output = check_output(['juju', 'config', appname, '--model', token.modelname, '--format', 'json'], universal_newlines=True)
    return json.loads(output)
