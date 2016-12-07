
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
import json
import os
from subprocess import check_call, check_output, STDOUT, CalledProcessError
# import tempfile
import yaml

from juju_controllers import maas, aws

from flask import abort


USER = os.environ.get('JUJU_ADMIN_USER')
PASSWORD = os.environ.get('JUJU_ADMIN_PASSWORD')


class JuJu_Token(object):
    def __init__(self, auth):
        self.username = auth.username
        self.password = auth.password
        self.admin = self.set_admin()
        self.c_name = None
        self.c_type = None
        self.c_access = None
        self.c_token = None
        self.m_name = None
        self.m_access = None

    def set_controller(self, c_name, c_type, c_access, c_token):
        self.c_name = c_name
        self.c_type = c_type
        self.c_access = c_access
        self.c_token = c_token

    def set_model(self, modelname, modelaccess):
        self.m_name = modelname
        self.m_access = modelaccess

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


def authenticate(auth, controller=None, modelname=None):
    token = JuJu_Token(auth)
    if controller is None and not token.admin:
        abort(403, {'message': 'Only admins are allowed to perform this operation!'})
    elif controller is None and token.admin:
        return token
    else:
        c_access = get_controller_access(token.username, token.password, controller)
        if c_access is None:
            abort(403, {'message': 'This controller does not exist or you do not have permission to see it!'})
        c_type, c_endpoint = get_controller_info(controller)
        if c_type == 'maas':
            c_token = maas.Token(c_endpoint, auth)
        elif c_type == 'aws':
            c_token = aws.Token(c_endpoint, auth)
        token.set_controller(controller, c_type, c_access, c_token)
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
def create_controller(c_type, name, region, credentials):
    if c_type == 'maas':
        output = maas.create_controller(name, region, credentials)
    elif c_type == 'aws':
        output = aws.create_controller(name, region, credentials)
    else:
        output = 'Incorrect controller type. Supported options are: maas, aws'
    return output


def delete_controller(token):
    return check_output(['juju', 'destroy-controller', '--destroy-all-models', token.c_name, '-y'])


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
def model_exists(token):
    data = json.loads(check_output(['juju', 'list-models', '--format', 'json']))
    return token.m_name in data.values()


def get_gui_url(token):
    return check_output(['juju', 'gui', '--no-browser', '--model', token.m_name],
                        universal_newlines=True, stderr=STDOUT).rstrip()


def create_model(token, ssh_key=None):
    # credentials = token.get_credentials()
    # tmp = tempfile.NamedTemporaryFile(mode="w+", delete=False)
    # tmp.write(json.dumps(credentials))
    # tmp.close()  # deletes the file
    # check_call(['juju', 'add-credential', '--replace', token.c_name, '-f', tmp.name])
    check_call(['juju', 'add-model', token.m_name, '--credential', USER]) # token.username])
    check_call(['juju', 'grant', token.username, 'admin', token.m_name])
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
    return [(u['user-name'], u['access']) for u in users]


def get_admins():
    superusers = {}
    admins = []
    for controller in get_all_controllers():
        tempusers = []
        minimum_superusers = -1
        for user in get_users(controller):
            if user[1] == 'superuser':
                tempusers.append(user[1])
        superusers[controller] = tempusers
        if minimum_superusers == -1:
            minimum_superusers = len(tempusers)
        elif len(tempusers) < minimum_superusers:
            minimum_superusers = len(tempusers)
            minimum_controller = controller
    for admin in superusers[minimum_controller]:
        is_admin = True
        for controller, users in superusers.items():
            if admin not in users:
                is_admin = False
                break
        if is_admin:
            admins.append(admin)
    return admins
#####################################################################################
# To Check
#####################################################################################
def config(token, appname):
    output = check_output(['juju', 'config', appname, '--model', token.modelname, '--format', 'json'], universal_newlines=True)
    return json.loads(output)


def user_exists(username, modelname=None):
    exists = False
    if modelname:
        output = check_output(['juju', 'users', modelname, '--format', 'json'])
        if username in json.loads(output[:-1]):
            exists = True
    else:
        output = check_output(['juju', 'users', '--format', 'json'])
        if username in json.loads(output[1:-2]).values():
            exists = True
    return exists
