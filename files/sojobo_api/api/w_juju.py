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
# pylint: disable=c0111,c0301,c0325,c0103,r0204,r0913,r0902,e0401
import base64
import hashlib
from importlib import import_module
import json
import os
from subprocess import check_output, STDOUT, CalledProcessError
import asyncio
from flask import abort, Response
from sojobo_api.api import w_errors as errors
from sojobo_api import settings
from git import Repo
from juju.model import Model
from juju.controller import Controller
from juju.cloud import Cloud
from juju.errors import JujuAPIError
#from juju.client import client
from juju.client.connection import JujuData
################################################################################
# TENGU FUNCTIONS
################################################################################
class JuJu_Token(object):
    def __init__(self, auth):
        self.username = auth.username
        self.password = auth.password
        self.is_admin = self.set_admin()
        self.c_name = None
        self.c_access = None
        self.c_token = None
        self.c_connection = None
        self.m_name = None
        self.m_access = None
        self.m_uuid = None
        self.m_connection = None


    def set_controller(self, c_name):
        c_type, c_endpoint = controller_info(c_name)
        self.c_name = c_name
        self.c_access = get_controller_access(self, self.username)
        self.c_token = getattr(get_controller_types()[c_type], 'Token')(c_endpoint, self.username, self.password)
        self.c_connection = execute_task(connect_controller, self)
        return self


    def set_model(self, modelname):
        self.m_name = modelname
        self.m_access = get_model_access(self, self.username)
        self.m_uuid = execute_task(get_model_uuid(self))
        self.m_connection = execute_task(connect_model, self)
        return self


    def m_shared_name(self):
        return "{}/{}".format(settings.JUJU_ADMIN_USER, self.m_name)


    def set_admin(self):
        return self.username == settings.JUJU_ADMIN_USER and self.password == settings.JUJU_ADMIN_PASSWORD


    def disconnect(self):
        if self.m_connection is not None:
            self.m_connection.disconnect()
        if self.c_connection is not None:
            self.c_connection.disconnect()


def get_api_key():
    with open('{}/api-key'.format(settings.SOJOBO_API_DIR), 'r') as key:
        apikey = key.readlines()[0]
    return apikey


def get_api_dir():
    return settings.SOJOBO_API_DIR


def get_api_user():
    return settings.SOJOBO_USER


def get_controller_types():
    c_list = {}
    for f_path in os.listdir('{}/controllers'.format(settings.SOJOBO_API_DIR)):
        if 'controller_' in f_path and '.pyc' not in f_path:
            name = f_path.split('.')[0]
            c_list[name.split('_')[1]] = import_module('sojobo_api.controllers.{}'.format(name))
    return c_list


def execute_task(command, *args):
    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    result = loop.run_until_complete(command(*args))
    return result


def create_response(http_code, return_object):
    return Response(
        json.dumps(return_object),
        status=http_code,
        mimetype='application/json',
    )


def output_pass(commands, controller=None, model=None):
    if controller is not None and model is not None:
        commands.extend(['-m', '{}:{}'.format(controller, model)])
    elif controller is not None:
        commands.extend(['-c', controller])
    try:
        result = check_output(commands, input=bytes('{}\n'.format(settings.JUJU_ADMIN_PASSWORD), 'utf-8'), stderr=STDOUT).decode('utf-8')
        if 'please enter password' in result:
            result = result.split('\n', 1)[1]
    except CalledProcessError as e:
        msg = e.output.decode('utf-8')
        if 'no credentials provided' in msg:
            check_output(['juju', 'login', settings.JUJU_ADMIN_USER, '-c', controller], input=bytes('{}\n'.format(settings.JUJU_ADMIN_PASSWORD), 'utf-8'))
            result = output_pass(commands)
        else:
            error = errors.cmd_error(msg)
            abort(error[0], error[1])
    return result


def check_input(data):
    if data is not None:
        items = data.split(':', 1)
        if len(items) > 1 and items[0].lower() not in ['local', 'github', 'lxd', 'kvm']:
            error = errors.invalid_option(items[0])
            abort(error[0], error[1])
        else:
            for item in items:
                if not all(x.isalpha() or x.isdigit() or x == '-' for x in item):
                    error = errors.invalid_input()
                    abort(error[0], error[1])
            result = data.lower()
    else:
        result = None
    return result


# def check_access(access):
#     acc = access.lower()
#     if c_access_exists(acc) or m_access_exists(acc):
#         return acc
#     else:
#         error = errors.invalid_access('access')
#         abort(error[0], error[1])

async def connect_controller(token): #pylint: disable=e0001
    controller = Controller()
    await controller.connect(
        token.url,
        settings.JUJU_ADMIN_USER,
        settings.JUJU_ADMIN_PASSWORD,
        None,)
    return controller


async def connect_model(token): #pylint: disable=e0001
    model = Model()
    await model.connect(
        token.url,
        token.m_uuid,
        settings.JUJU_ADMIN_USER,
        settings.JUJU_ADMIN_PASSWORD,)
    return model


async def check_login(auth, controller=None):
    if auth.username == settings.JUJU_ADMIN_USER:
        result = auth.password == settings.JUJU_ADMIN_PASSWORD
    elif controller is not None:
        try:
            controller = Controller()
            controller_endpoint = controller_info(controller)[1]
            await controller.connect(controller_endpoint, auth.username, auth.password)
            await controller.disconnect()
            result = True
        except JujuAPIError as e:
            result = 'invalid entity name or password' in e.message.decode('utf-8')
    else:
        result = False
    return result


async def authenticate(api_key, auth, controller=None, modelname=None):
    if api_key != get_api_key() or not await check_login(auth, controller):
        error = errors.unauthorized()
        abort(error[0], error[1])
    token = JuJu_Token(auth)
    if controller is not None and await controller_exists(controller):
        if token.set_controller(controller).c_access is None:
            error = errors.no_access('controller')
            abort(error[0], error[1])
        if modelname is not None and await model_exists(token, modelname):
            if token.set_model(modelname).m_access is None:
                error = errors.no_access('model')
                abort(error[0], error[1])
        elif modelname is not None and not await model_exists(token, modelname):
            error = errors.does_not_exist('model')
            abort(error[0], error[1])
    elif not await controller_exists(controller) and controller is not None:
        error = errors.does_not_exist('controller')
        abort(error[0], error[1])
    return token
###############################################################################
# CONTROLLER FUNCTIONS
###############################################################################
async def cloud_supports_series(token, series):
    if series is None:
        return True
    else:
        return series in get_controller_types()[token.c_token.type].get_supported_series()


async def check_c_type(c_type):
    if check_input(c_type) in get_controller_types().keys():
        return c_type.lower()
    else:
        error = errors.invalid_controller(c_type)
        abort(error[0], error[1])


# libjuju: nok (TODO change user password wel, eerst aanpassingen aan subordinates)
async def create_controller(c_type, name, region, credentials):
    get_controller_types()[c_type].create_controller(name, region, credentials)
    pswd = os.environ.get('JUJU_ADMIN_PASSWORD')
    try:
        con = await controller_info(name)
        controller = Controller()
        await controller.connect(
            con[1],
            'admin',
            '',
            None,)
        await controller.change_user_password('admin', pswd)
    except NotImplementedError:
        check_output(['juju', 'change-user-password', 'admin', '-c', name], input=bytes('{}\n{}\n'.format(pswd, pswd), 'utf-8'))


async def controller_info(c_name):
    jujudata = JujuData()
    controllers = jujudata.controllers()[c_name]
    return controllers['cloud'], controllers['api-endpoints'][0]


async def delete_controller(token):
    try:
        controller = token.c_connection
        await controller.destroy(True)
        cloud = Cloud()
        await cloud.remove_credential(token.c_name)
    except NotImplementedError:
        output_pass(['juju', 'destroy-controller', '-y'], token.c_name)
        output_pass(['juju', 'remove-credential', token.c_token.type, token.c_name])


async def get_all_controllers():
    try:
        jujudata = JujuData()
        result = jujudata.controllers()
    except FileNotFoundError:
        result = []
    return result


async def controller_exists(c_name):
    return c_name in await get_all_controllers()


async def get_controller_access(token, username):
    try:
        controller = token.c_connection()
        user = await controller.get_user(username, True)
        result = user.serialize()['results'][0].serialize()['result'].serialize()['access']
    except NotImplementedError:
        users = json.loads(output_pass(['juju', 'users', '--format', 'json'], token.c_name))
        result = None
        for user in users:
            if user['user-name'] == username:
                access = user['access']
                if await c_access_exists(access):
                    result = access
    except json.decoder.JSONDecodeError as e:
        error = errors.cmd_error(e)
        abort(error[0], error[1])
    return result


async def get_controllers_info(token):
    result = await get_all_controllers()
    output = []
    for c in result:
        if token.set_controller(c).c_access is not None:
            output.append(await get_controller_info(token))
    return output


async def get_controller_info(token):
    if token.c_access is not None:
        models = await get_models_info(token)
        users = await get_users_controller(token)
        result = {'name': token.c_name, 'type': token.c_token.type, 'models': models,
                  'users': users}
    else:
        result = None
    return result


async def c_access_exists(access):
    return access in ['login', 'add-model', 'superuser']


#libjuju : nog geen wrapper geschreven voor get_users()
async def get_controller_superusers(token):
    try:
        controller = token.c_connection()
        users = await controller.get_users()
        return [u['properties']['username']['type'] for u in users if u['properties']['access']['type'] == 'superuser']
    except NotImplementedError:
        users = json.loads(output_pass(['juju', 'users', '--format', 'json'], token.c_name))
        return [u['user-name'] for u in users if u['access'] == 'superuser']
    except json.decoder.JSONDecodeError as e:
        error = errors.cmd_error(e)
        abort(error[0], error[1])
###############################################################################
# MODEL FUNCTIONS
###############################################################################
async def get_all_models(token):
    try:
        controller = token.c_connection
        models = await controller.get_models()
        return [model.serialize()['model'].serialize() for model in models.serialize()['user-models']]
    except NotImplementedError:
        try:
            jujudata = JujuData()
            return jujudata.models()[token.c_name].keys()
        except FileNotFoundError:
            return []
    except json.decoder.JSONDecodeError as e:
        error = errors.cmd_error(e)
        abort(error[0], error[1])


async def model_exists(token, model):
    return model in await get_all_models(token)


async def get_model_uuid(token):
    for model in await get_all_models(token):
        if model['name'] == token.m_name:
            return model['uuid']


async def get_model_access(token, username):
    access = None
    try:
        controller = token.c_connection
        models = await controller.get_all_models()
        for model in models:
            model.get_info()
    except NotImplementedError:
        for model in json.loads(output_pass(['juju', 'models', '--format', 'json'], token.c_name))['models']:
            if model['name'] == token.m_name and username in model['users'].keys():
                access = model['users'][username]['access']
                break
        return access
    except json.decoder.JSONDecodeError as e:
        error = errors.cmd_error(e)
        abort(error[0], error[1])


# async def m_access_exists(access):
#     return access in ['read', 'write', 'admin']


async def get_models_info(token):
    result = await get_all_models(token)
    output = []
    for m in result:
        if token.set_model(m).m_access is not None:
            output.append(await get_model_info(token))
    return output


async def get_model_info(token):
    if token.m_access is not None:
        users = await get_users_model(token)
        ssh = await get_ssh_keys(token)
        applications = await get_applications_info(token)
        machines = await get_machines_info(token)
        gui = await get_gui_url(token)
        result = {'name': token.m_name, 'users': users, 'ssh-keys': ssh,
                  'applications': applications, 'machines': machines,
                  'juju-gui-url': gui}
    else:
        result = None
    return result


async def get_ssh_keys(token):
    try:
        model = token.m_connection
        return await model.get_ssh_key()
    except NotImplementedError:
        return output_pass(['juju', 'ssh-keys', '--full'], token.c_name, token.m_name).split('\n')[1:-1]


async def get_applications_info(token):
    try:
        model = token.m_connection
        data = model.state.state
        result = []
        for app in data['application'].keys():
            result.append(await get_application_info(token, app))
        return result
    except json.decoder.JSONDecodeError as e:
        error = errors.cmd_error(e)
        abort(error[0], error[1])


async def get_units_info(token, application):
    try:
        model = token.m_connection
        data = model.state.state['unit']
        units = []
        result = []
        for unit in data.keys():
            if unit.startswith(application):
                units.append(data[unit][0])
        for u in units:
            ports = await get_unit_ports(u)
            result.append({'name': u['name'],
                           'machine': u['machine-id'],
                           'ip': u['public-address'],
                           'ports': ports})
        return result
    except json.decoder.JSONDecodeError as e:
        error = errors.cmd_error(e)
        abort(error[0], error[1])


#libjuju geen manier om gui te verkrijgen of juju gui methode
async def get_gui_url(token):
    try:
        data = output_pass(['juju', 'gui', '--no-browser'], token.c_name, token.m_name).rstrip().split(':')
        return 'https:{}:{}'.format(data[2], data[3])
    except json.decoder.JSONDecodeError as e:
        error = errors.cmd_error(e)
        abort(error[0], error[1])


async def create_model(token, model, ssh_key=None):
    try:
        controller = token.c_connection
        await controller.add_model(model, token.c_name)
    except NotImplementedError:
        output_pass(['juju', 'add-model', model], token.c_name)
    if ssh_key is not None:
        await add_ssh_key(token, ssh_key)
    await add_to_model(token.set_model(model), token.username, 'admin')
    cont = await get_controller_superusers(token)
    for user in cont:
        await add_to_model(token, user, 'admin')


async def delete_model(token):
    try:
        controller = token.c_connection
        await controller.destroy_models(token.m_uuid)
    except NotImplementedError:
        output_pass(['juju', 'destroy-model', '-y', '{}:{}'.format(token.c_name, token.m_name)])


async def add_ssh_key(token, ssh_key):
    try:
        model = token.m_connection
        await model.add_ssh_key(ssh_key)
    except NotImplementedError:
        output_pass(['juju', 'add-ssh-key', '"{}"'.format(ssh_key)], token.c_name, token.m_name)


async def remove_ssh_key(token, ssh_key):
    key = base64.b64decode(bytes(ssh_key.strip().split()[1].encode('ascii')))
    fp_plain = hashlib.md5(key).hexdigest()
    fingerprint = ':'.join(a+b for a, b in zip(fp_plain[::2], fp_plain[1::2]))
    try:
        model = token.m_connection
        await model.add_ssh_key(fingerprint)
    except NotImplementedError:
        output_pass(['juju', 'remove-ssh-key', fingerprint], token.c_name, token.m_name)

#####################################################################################
# Machines FUNCTIONS
#####################################################################################
async def get_machines_info(token):
    try:
        model = token.m_connection
        data = model.state.machines.keys()
        return [get_machine_info(token, m) for m in data if not 'lxd' in m]
    except json.decoder.JSONDecodeError as e:
        error = errors.cmd_error(e)
        abort(error[0], error[1])


async def get_machine_entity(token, machine):
    model = token.m_connection
    for app in model.state.machines.items():
        if app[0] == machine:
            return app[1]


async def get_machine_info(token, machine):
    try:
        model = token.m_connection
        data = model.state.state['machine']
        machine_data = data[machine][0]
        containers = []
        if not 'lxd' in machine:
            lxd = []
            for key in data.keys():
                if key.startswith('{}/lxd'.format(machine)):
                    lxd.append(key)
            if lxd != []:
                for cont in lxd:
                    cont_data = data[cont][0]
                    ip = await get_machine_ip(cont_data, 'local_cloud')
                    containers.append({'name': cont, 'instance-id': cont_data['instance-id'], 'ip': ip, 'series': cont_data['series']})
            mach_ip = await get_machine_ip(machine_data, 'public')
            result = {'name': machine, 'instance-id': machine_data['instance-id'], 'ip': mach_ip, 'series': machine_data['series'], 'containers': containers}
        else:
            mach_ip = await get_machine_ip(machine_data, 'local_cloud')
            result = {'name': machine, 'instance-id': machine_data['instance-id'], 'ip': mach_ip, 'series': machine_data['series']}
    except KeyError:
        result = {'name': machine, 'instance-id': 'Unknown', 'ip': 'Unknown', 'series': 'Unknown', 'containers': 'Unknown'}
    except json.decoder.JSONDecodeError as e:
        error = errors.cmd_error(e)
        abort(error[0], error[1])
    return result


async def get_machine_ip(machine_data, cloud):
    for dns in machine_data['addresses']:
        if dns['scope'] == cloud:
            dns_name = dns['value']
    return dns_name


async def add_machine(token, ser=None, cont=None):
    try:
        model = token.m_connection
        await model.add_machine(series=ser, constraints=cont)
    except NotImplementedError:
        if ser is None and cont is None:
            result = output_pass(['juju', 'add-machine'], token.c_name, token.m_name)
        elif ser is None:
            commands = ['juju', 'add-machine', '--constraints']
            commands.extend(cont)
            result = output_pass(commands, token.c_name, token.m_name)
        elif cont is None:
            result = output_pass(['juju', 'add-machine', '--series', ser], token.c_name, token.m_name)
        else:
            commands = ['juju', 'add-machine', '--series', ser, '--constraints']
            commands.extend(cont)
            result = output_pass(commands, token.c_name, token.m_name)
        return result


async def machine_exists(token, machine):
    try:
        model = token.m_connection
        data = model.state.state['machine'].keys()
        return machine in data
    except json.decoder.JSONDecodeError as e:
        error = errors.cmd_error(e)
        abort(error[0], error[1])


async def get_machine_series(token, machine):
    try:
        data = await get_machine_info(token, machine)
        return data['series']
    except json.decoder.JSONDecodeError as e:
        error = errors.cmd_error(e)
        abort(error[0], error[1])


async def machine_matches_series(token, machine, series):
    if machine is None or series is None:
        return True
    else:
        return series == await get_machine_series(token, machine)


async def remove_machine(token, machine):
    try:
        machine = await get_machine_entity(token, machine)
        machine.destroy(force=True)
    except NotImplementedError:
        output_pass(['juju', 'remove-machine', '--force', machine], token.c_name, token.m_name)


#####################################################################################
# APPLICATION FUNCTIONS
#####################################################################################
async def app_exists(token, app_name):
    try:
        model_info = await get_model_info(token)
        return app_name in model_info['applications'].keys()
    except NotImplementedError:
        data = json.loads(output_pass(['juju', 'status', '--format', 'json'], token.c_name, token.m_name))
        return app_name in data['applications'].keys()
    except json.decoder.JSONDecodeError as e:
        error = errors.cmd_error(e)
        abort(error[0], error[1])


# def deploy_bundle(token, bundle):
#     with open('{}/files/data.yml'.format(settings.SOJOBO_API_DIR), 'w+') as outfile:
#         yaml.dump(bundle, outfile, default_flow_style=False)
#     output_pass(['juju', 'deploy', '/opt/sojobo_api/files/data.yml'], token.c_name, token.m_name)


async def deploy_app(token, app_name, ser=None, tar=None):
    try:
        model = token.m_connection
        await model.deploy(app_name, series=ser, target=tar)
    except NotImplementedError:
        if 'local:' in app_name:
            app_name = app_name.replace('local:', '{}/'.format(settings.LOCAL_CHARM_DIR))
        elif 'github:' in app_name:
            Repo.clone(app_name.split(':', 1)[1], settings.LOCAL_CHARM_DIR)
            app_name = '{}/{}'.format(settings.LOCAL_CHARM_DIR, app_name.split('/')[-1])
        if tar is None and ser is None:
            output_pass(['juju', 'deploy', app_name], token.c_name, token.m_name)
        elif tar is None:
            output_pass(['juju', 'deploy', app_name, '--series', ser], token.c_name, token.m_name)
        elif ser is None:
            output_pass(['juju', 'deploy', app_name, '--to', tar], token.c_name, token.m_name)
        else:
            output_pass(['juju', 'deploy', app_name, '--series', ser, '--to', tar], token.c_name, token.m_name)


async def get_application_entity(token, app_name):
    model = token.m_connection
    for app in model.state.applications.items():
        if app[0] == app_name:
            return app[1]


async def remove_app(token, app_name):
    try:
        app = await get_application_entity(token, app_name)
        await app.remove()
    except NotImplementedError:
        output_pass(['juju', 'remove-application', app_name], token.c_name, token.m_name)


async def get_application_info(token, application):
    try:
        model = token.m_connection
        data = model.state.state
        for application in data['application'].items():
            if application[0] == application:
                app = application[1]
                res1 = {'name': app[0]['name'], 'relations': [], 'charm': app[0]['charm-url'], 'exposed': app[0]['exposed'],
                        'series': app[0]['charm-url'].split(":")[1].split("/")[0], 'status': app[0]['status']['current']}
                for rels in data['relation'].values():
                    keys = rels[0]['key'].split(" ")
                    if len(keys) == 1 and app[0]['name'] == keys[0].split(":")[0]:
                        res1['relations'].extend([{'interface': keys[0].split(":")[1], 'with': keys[0].split(":")[0]}])
                    elif len(keys) == 2 and app[0]['name'] == keys[0].split(":")[0]:
                        res1['relations'].extend([{'interface': keys[1].split(":")[1], 'with': keys[1].split(":")[0]}])
                    elif len(keys) == 2 and app[0]['name'] == keys[1].split(":")[0]:
                        res1['relations'].extend([{'interface': keys[0].split(":")[1], 'with': keys[0].split(":")[0]}])
                res1['units'] = await get_units_info(model, app[0]['name'])
        return res1
    except json.decoder.JSONDecodeError as e:
        error = errors.cmd_error(e)
        abort(error[0], error[1])


async def get_unit_info(token, application, unitnumber):
    data = await get_application_info(token, application)
    for u in data['units']:
        if u['name'] == '{}/{}'.format(application, unitnumber):
            return u
    return {}


# def unit_exists(token, application, unitnumber):
#     data = get_application_info(token, application)
#     for u in data['units']:
#         if u['name'] == '{}/{}'.format(application, unitnumber):
#             return u


async def add_unit(token, app_name, target=None):
    try:
        application = await get_application_entity(token, app_name)
        await application.add_unit(count=1, to=target)
    except NotImplementedError:
        if target is None:
            return output_pass(['juju', 'add-unit', app_name], token.c_name, token.m_name)
        else:
            return output_pass(['juju', 'add-unit', app_name, '--to', target])


async def remove_unit(token, application, unit_number):
    try:
        app = await get_application_entity(token, application)
        unit = '{}/{}'.format(application, unit_number)
        await app.destroy_unit(unit)
    except NotImplementedError:
        return output_pass(['juju', 'remove-unit', '{}/{}'.format(application, unit_number)], token.c_name, token.m_name)


async def get_unit_ports(unit):
    ports = []
    for port in unit['ports']:
        ports.append(port)
    return ports


async def get_relations_info(token):
    data = await get_applications_info(token)
    return [{'name': a['name'], 'relations': a['relations']} for a in data]


async def add_relation(token, app1, app2):
    try:
        model = token.m_connection
        await model.add_relation(app1, app2)
    except NotImplementedError:
        output_pass(['juju', 'add-relation', app1, app2], token.c_name, token.m_name)


async def remove_relation(token, app1, app2):
    try:
        model = token.m_connection
        data = model.state.state
        application = await get_application_entity(token, app1)
        if app1 == app2:
            for relation in data['relation'].items():
                keys = relation[1][0]['keys'].split(':')
                await application.destroy_relation(keys[1], '{}:{}'.format(keys[0], keys[1]))
        else:
            for relation in data['relation'].items():
                keys = relation[1][0]['keys'].split(' ')
                if keys[0].startswith(app1):
                    await application.destroy_relation(keys[0].split(':')[1], keys[1])
                elif keys[1].startswith(app1):
                    await application.destroy_relation(keys[1].split(':')[1], keys[0])
    except NotImplementedError:
        output_pass(['juju', 'remove-relation', app1, app2], token.c_name, token.m_name)


# async def app_supports_series(app_name, series):
#     if series is None:
#         supports = True
#     elif 'local:' in app_name:
#         with open('{}/{}/metadata.yaml'.format(settings.LOCAL_CHARM_DIR, app_name.split(':')[1])) as data:
#             supports = series in yaml.load(data)['series']
#     else:
#         supports = False
#         data = requests.get('https://api.jujucharms.com/v4/{}/expand-id'.format(app_name))
#         for value in json.loads(data.text):
#             if series in value['Id']:
#                 supports = True
#                 break
#     return supports
###############################################################################
# USER FUNCTIONS
###############################################################################
async def create_user(token, username, password):
    try:
        controller = token.c_connection
        await controller.add_user(username)
        await change_user_password(token, username, password)
    except NotImplementedError:
        for controller in get_all_controllers():
            output_pass(['juju', 'add-user', username], controller)
            output_pass(['juju', 'revoke', username, 'login'], controller)
        await change_user_password(token, username, password)


async def delete_user(token, username):
    try:
        controller = token.c_connection
        await controller.disable_user(username)
    except NotImplementedError:
        for controller in await get_all_controllers():
            output_pass(['juju', 'remove-user', username, '-y'], controller)


async def change_user_password(token, username, password):
    try:
        controller = token.c_connection
        await controller.change_user_password(username, password)
    except NotImplementedError:
        for controller in get_all_controllers():
            check_output(['juju', 'change-user-password', username, '-c', controller],
                         input=bytes('{}\n{}\n'.format(password, password), 'utf-8'))


#libjuju: nog gene methode om get_all_users te implementeren
async def get_users_controller(token):
    try:
        if token.c_access == 'superuser':
            data = json.loads(output_pass(['juju', 'list-users', '--format', 'json'], token.c_name))
            users = [{'name': u['user-name'], 'access': u['access']} for u in data]
        elif token.c_access is not None:
            users = [{'name': token.username, 'access': token.c_access}]
        else:
            users = None
        return users
    except json.decoder.JSONDecodeError as e:
        error = errors.cmd_error(e)
        abort(error[0], error[1])


#libjuju: nog gene methode om get_all_users te implementeren
async def get_users_model(token):
    try:
        if token.m_access == 'admin' or token.m_access == 'write':
            data = await get_all_models(token)
            for model in data:
                if model['name'] == token.m_name:
                    users_info = model['users']
                    break
            users = [{'name': k, 'access': v['access']} for k, v in users_info.items()]
        elif token.m_access is not None:
            users = [{'name': token.username, 'access': token.m_access}]
        else:
            users = None
        return users
    except json.decoder.JSONDecodeError as e:
        error = errors.cmd_error(e)
        abort(error[0], error[1])


async def add_to_controller(token, username, access):
    controller = token.c_connection
    await controller.grant(username, access)


async def remove_from_controller(token, username):
    controller = token.c_connection
    await controller.revoke(username)


async def add_to_model(token, username, access):
    model = token.m_connection
    await model.grant(username, access)


async def remove_from_model(token, username):
    model = token.m_connection
    await model.revoke(username)


async def user_exists(username):
    return username == settings.JUJU_ADMIN_USER or username in await get_all_users()


#libjuju: geen andere methode om users op te vragen atm
async def get_all_users():
    try:
        users = json.loads(output_pass(['juju', 'users', '--all', '--format', 'json'], await get_all_controllers()[0]))
        result = [user['user-name'] for user in users]
    except IndexError:
        result = [settings.JUJU_ADMIN_USER]
    except json.decoder.JSONDecodeError as e:
        error = errors.cmd_error(e)
        abort(error[0], error[1])
    return result


async def get_users_info(token):
    result = []
    for u in await get_all_users():
        ui = await get_user_info(token, u)
        result.append(ui)
    return result


async def get_user_info(token, username):
    user_acc = await get_controllers_access(token, username)
    return {'name': username, 'controllers': user_acc}


async def get_controllers_access(token, username):
    controllers = []
    for controller in await get_all_controllers():
        access = await get_controller_access(token.set_controller(controller), username)
        if access is not None:
            model_acc = await get_models_access(token, username)
            controllers.append({'name': controller, 'type': token.c_token.type, 'access': access,
                                'models': model_acc})
    return controllers


async def get_ucontroller_access(token, username):
    acc = await get_controller_access(token, username)
    mod = await get_models_access(token, username)
    return {'name': token.c_name,
            'access': acc,
            'models': mod}


async def get_models_access(token, username):
    models = []
    for model in await get_all_models(token):
        access = await get_model_access(token.set_model(model), username)
        if access is not None:
            models.append({'name': model, 'access': access})
    return models


async def get_umodel_access(token, username):
    mod_acc = await get_model_access(token, username)
    return {'name': token.m_name, 'access': mod_acc}
