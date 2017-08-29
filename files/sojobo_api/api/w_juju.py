#!/usr/bin/python3.6
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
# pylint: disable=c0111,c0301,c0325,c0103,r0204,r0913,r0902,e0401,C0302
import asyncio
from importlib import import_module
import os
# import tempfile
# import shutil
from subprocess import check_output, check_call, Popen
import json
from pathlib import Path
import yaml
from asyncio_extras import async_contextmanager
from flask import abort, Response
from juju import tag
from juju.controller import Controller
from juju.errors import JujuAPIError, JujuError
from juju.model import Model
from sojobo_api.api import w_errors as errors, w_datastore as datastore
from sojobo_api import settings
################################################################################
# TENGU FUNCTIONS
################################################################################
class JuJu_Token(object):  #pylint: disable=R0903
    def __init__(self, auth):
        self.username = auth.username
        self.password = auth.password
        self.is_admin = self.set_admin()

    def set_admin(self):
        return self.username == settings.JUJU_ADMIN_USER and self.password == settings.JUJU_ADMIN_PASSWORD


class Controller_Connection(object):
    def __init__(self, token, c_name):
        self.c_name = c_name
        self.c_access = datastore.get_controller_access(c_name, token.username)
        self.c_connection = Controller()
        con = datastore.get_controller(c_name)
        self.c_type = con['type']
        self.endpoint = con['endpoints'][0]
        self.c_cacert = con['ca-cert']
        self.c_token = getattr(get_controller_types()[self.c_type], 'Token')(self.endpoint, token.username, token.password)

    async def set_controller(self, token, c_name):
        await self.c_connection.disconnect()
        self.c_name = c_name
        self.c_access = datastore.get_controller_access(token.username, c_name)
        self.c_connection = Controller()
        con = datastore.get_controller(c_name)
        self.c_type = con['type']
        self.endpoint = con['endpoints'][0]
        self.c_cacert = con['ca-cert']
        self.c_token = getattr(get_controller_types()[self.c_type],
                               'Token')(self.endpoint, token.username, token.password)

    @async_contextmanager
    async def connect(self, token):
        nested = False
        if self.c_connection.connection is None or not self.c_connection.connection.is_open:
            await self.c_connection.connect(self.endpoint, token.username, token.password, self.c_cacert)
        else:
            nested = True
        yield self.c_connection  #pylint: disable=E1700
        if not nested:
            await self.c_connection.disconnect()


class Model_Connection(object):
    def __init__(self, token, controller, model):
        con = datastore.get_controller(controller)
        self.c_endpoint = con['endpoints'][0]
        self.c_cacert = con['ca-cert']
        self.m_name = model
        self.m_access = datastore.get_model_access(controller, self.m_name, token.username)
        self.m_uuid = datastore.get_model(controller, self.m_name)['uuid']
        self.m_connection = Model()

    async def set_model(self, token, controller, modelname):
        await self.m_connection.disconnect()
        self.m_name = modelname
        self.m_uuid = datastore.get_model(controller, self.m_name)['uuid']
        self.m_connection = Model()
        self.m_access = datastore.get_model_access(controller, self.m_name, token.username)

    @async_contextmanager
    async def connect(self, token):
        nested = False
        if self.m_connection.connection is None or not self.m_connection.connection.is_open:
            await self.m_connection.connect(self.c_endpoint, self.m_uuid,
                                            token.username, token.password, self.c_cacert)
        else:
            nested = True
        yield self.m_connection  #pylint: disable=E1700
        if not nested:
            await self.m_connection.disconnect()


def get_controller_types():
    c_list = {}
    for f_path in os.listdir('{}/controllers'.format(settings.SOJOBO_API_DIR)):
        if 'controller_' in f_path and '.pyc' not in f_path:
            name = f_path.split('.')[0]
            c_list[name.split('_')[1]] = import_module('sojobo_api.controllers.{}'.format(name))
    return c_list


def execute_task(command, *args, **kwargs):
    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    result = loop.run_until_complete(command(*args, **kwargs))
    return result


def create_response(http_code, return_object, is_json=False):
    if not is_json:
        return_object = json.dumps(return_object)
    return Response(
        return_object,
        status=http_code,
        mimetype='application/json',
    )


def check_input(data):
    if not data:
        error = errors.empty()
        abort(error[0], error[1])
    else:
        items = data.split(':', 1)
        if len(items) > 1 and items[0].lower() not in ['local', 'github', 'lxd', 'kvm']:
            error = errors.invalid_option(items[0])
            abort(error[0], error[1])
        else:
            for item in items:
                if not all(x.isalpha() or x.isdigit() or x == '-' for x in item):
                    error = errors.invalid_input()
                    abort(error[0], error[1])
            return data.lower()


async def authenticate(api_key, auth):
    error = errors.unauthorized()
    if api_key == settings.API_KEY:
        if auth is None:
            abort(error[0], error[1])
        token = JuJu_Token(auth)
        if token.is_admin:
            return token
        else:
            try:
                cont_name = list(await get_all_controllers())[0]
                controller = Controller_Connection(token, cont_name)
                async with controller.connect(token):  #pylint: disable=E1701
                    pass
                return token
            except JujuAPIError:
                abort(error[0], error[1])
    else:
        abort(error[0], error[1])


async def authorize(token, controller, model=None):
    if not await controller_exists(controller):
        error = errors.does_not_exist('controller')
        abort(error[0], error[1])
    else:
        con = Controller_Connection(token, controller)
        if con.c_access not in ['login', 'add-model', 'superuser']:
            error = errors.does_not_exist('controller')
            abort(error[0], error[1])
    if model and not await model_exists(token, con, model):
        error = errors.does_not_exist('model')
        abort(error[0], error[1])
    elif model:
        mod = Model_Connection(token, controller, model)
        if mod.m_access not in ['read', 'write', 'admin']:
            error = errors.does_not_exist('model')
            abort(error[0], error[1])
        return con, mod
    return con
###############################################################################
# CONTROLLER FUNCTIONS
###############################################################################
async def cloud_supports_series(controller_connection, series):
    if series is None:
        return True
    else:
        return series in get_controller_types()[controller_connection.c_token.type].get_supported_series()


async def check_c_type(c_type):
    if check_input(c_type) in get_controller_types().keys():
        return c_type.lower()
    else:
        error = errors.invalid_controller(c_type)
        abort(error[0], error[1])


async def create_controller(token, c_type, name, region, credentials):
    get_controller_types()[c_type].create_controller(name, region, credentials)
    pswd = settings.JUJU_ADMIN_PASSWORD
    check_output(['juju', 'change-user-password', 'admin', '-c', name],
                 input=bytes('{}\n{}\n'.format(pswd, pswd), 'utf-8'))
    with open(os.path.join(str(Path.home()), '.local', 'share', 'juju', 'controllers.yaml'), 'r') as data:
        con_data = yaml.load(data)
        datastore.create_controller(
            name,
            c_type,
            con_data['controllers'][name]['api-endpoints'],
            con_data['controllers'][name]['uuid'],
            con_data['controllers'][name]['ca-cert'],
            con_data['controllers'][name]['region'])
    datastore.add_user_to_controller(name, 'admin', 'superuser')
    controller = Controller_Connection(token, name)
    result_cred = await generate_cred_file(c_type, 'admin', credentials)
    datastore.add_credential('admin', result_cred)
    for model in await get_all_models(token, controller):
        datastore.add_model_to_controller(name, model['name'])
        datastore.set_model_state(name, model['name'], 'ready', model['uuid'])
        datastore.set_model_access(name, model['name'], token.username, 'admin')
    return await get_controller_info(token, controller)


async def generate_cred_file(c_type, name, credentials):
    return get_controller_types()[c_type].generate_cred_file(name, credentials)


async def delete_controller(con):
    #controller = con.c_connection
    #await controller.destroy(True)
    check_output(['juju', 'login', con.c_name, '-u', settings.JUJU_ADMIN_USER], input=bytes('{}\n'.format(settings.JUJU_ADMIN_PASSWORD), 'utf-8'))
    check_call(['juju', 'destroy-controller', '-y', con.c_name, '--destroy-all-models'])
    check_call(['juju', 'remove-credential', con.c_type, con.c_name])
    datastore.destroy_controller(con.c_name)


async def get_all_controllers():
    return datastore.get_all_controllers()


async def controller_exists(c_name):
    return c_name in list(await get_all_controllers())


async def get_controller_access(con, username):
    return datastore.get_controller_access(con.c_name, username)


async def get_controllers_info():
    return [datastore.get_controller(c) for c in datastore.get_all_controllers()]


async def get_controller_info(token, controller):
    if controller.c_access is not None:
        models = await get_models_info(token, controller)
        users = await get_users_controller(controller.c_name)
        result = {'name': controller.c_name, 'type': controller.c_token.type, 'models': models,
                  'users': users}
    else:
        result = None
    return result


async def get_controller_superusers(controller):
    users = datastore.get_controller_users(controller)
    result = []
    for user in users:
        if datastore.get_controller_access(controller, user['name']) == 'superuser':
            result.append(user['name'])
    return result


async def get_controller_type(c_name):
    controllers = await get_controllers_info()
    return controllers[c_name]['cloud']
###############################################################################
# MODEL FUNCTIONS
###############################################################################
async def get_all_models(token, controller):
    async with controller.connect(token) as juju:
        models = await juju.get_models()
    return [model.serialize()['model'].serialize() for model in models.serialize()['user-models']]


async def model_exists(token, controller, modelname):
    all_models = await get_all_models(token, controller)
    for model in all_models:
        if model['name'] == modelname:
            return True
    return False


async def get_model_uuid(token, controller, model):
    for mod in await get_all_models(token, controller):
        if mod['name'] == model.m_name:
            return mod['uuid']


async def get_model_access(model, controller, username):
    return datastore.get_model_access(controller, model, username)


async def get_models_info(token, controller):
    return await get_all_models(token, controller)


async def get_model_info(token, controller, model):
    state = datastore.check_model_state(controller.c_name, model.m_name)
    if state == 'ready':
        async with model.connect(token):
            users = await get_users_model(token, controller, model)
            ssh = await get_ssh_keys(token, model)
            applications = await get_applications_info(token, model)
            machines = await get_machines_info(token, model)
            gui = await get_gui_url(controller, model)
            credentials = await get_model_creds(token, model)
        return {'name': model.m_name, 'users': users, 'ssh-keys': ssh,
                'applications': applications, 'machines': machines, 'juju-gui-url' : gui,
                'status': datastore.check_model_state(controller.c_name, model.m_name), 'credentials' : credentials}
    elif state == 'accepted' or state == 'error':
        return {'name': model.m_name, 'status': state, 'users' : {"user" : token.username, "access" : "admin"}}
    else:
        return {}


async def get_model_creds(token, model):
    async with model.connect(token) as juju:
        info = await juju.get_info()
    cloud_cred = info.serialize()['cloud-credential-tag']
    cloud_result = tag.untag('cloudcred-', cloud_cred)
    return get_cloud_response(cloud_result)


def get_cloud_response(data):
    values = data.split('_')
    if len(values) == 3:
        result = {'cloud' : values[0], 'user' : values[1], 'credential-name' : values[2]}
        return result
    return None


async def get_ssh_keys(token, model):
    async with model.connect(token) as juju:
        res = await juju.get_ssh_key(False)
    data = res.serialize()['results'][0].serialize()['result']
    if data is None:
        return []
    else:
        return data


async def get_ssh_keys_user(user):
    return datastore.get_ssh_keys(user)


async def get_applications_info(token, model):
    result = []
    async with model.connect(token) as juju:
        for data in juju.state.state.get('application', {}).values():
            res = {'name': data[0]['name'], 'relations': [], 'charm': data[0]['charm-url'], 'exposed': data[0]['exposed'],
                   'status': data[0]['status']}
            for rels in juju.state.state['relation'].values():
                keys = rels[0]['key'].split(" ")
                if len(keys) == 1 and data[0]['name'] == keys[0].split(":")[0]:
                    res['relations'].extend([{'interface': keys[0].split(":")[1], 'with': keys[0].split(":")[0]}])
                elif len(keys) == 2 and data[0]['name'] == keys[0].split(":")[0]:
                    res['relations'].extend([{'interface': keys[1].split(":")[1], 'with': keys[1].split(":")[0]}])
                elif len(keys) == 2 and data[0]['name'] == keys[1].split(":")[0]:
                    res['relations'].extend([{'interface': keys[0].split(":")[1], 'with': keys[0].split(":")[0]}])
            res['units'] = await get_units_info(token, model, data[0]['name'])
            result.append(res)
    return result


async def get_units_info(token, model, application):
    try:
        async with model.connect(token) as juju:
            data = juju.state.state['unit']
        units = []
        result = []
        for unit in data.keys():
            if unit.startswith(application):
                units.append(data[unit][0])
        for u in units:
            ports = await get_unit_ports(u)
            result.append({'name': u['name'],
                           'machine': u['machine-id'],
                           'public-ip': u['public-address'],
                           'private-ip': u['private-address'],
                           'series': u['series'],
                           'ports': ports})
        return result
    except KeyError:
        return []


async def get_public_ip_controller(token, controller):
    async with controller.connect(token) as juju:
        servers = juju.info['servers']
    for server_list in servers:
        for server in server_list:
            if server['scope'] == 'public' and server['type'] == 'ipv4':
                return server['value']



#libjuju geen manier om gui te verkrijgen of juju gui methode
async def get_gui_url(controller, model):
    return 'https://{}/gui/{}'.format(controller.endpoint, model.m_uuid)


async def create_model(token, controller, model, credentials):
    state = datastore.check_model_state(controller, model)
    if state != "error":
        code, response = errors.already_exists('model')
    elif credentials in datastore.get_credential_keys(token.username):
        datastore.add_model_to_controller(controller, model)
        datastore.set_model_state(controller, model, 'accepted')
        datastore.set_model_access(controller, model, token.username, 'admin')
        Popen(["python3.6", "{}/scripts/add_model.py".format(settings.SOJOBO_API_DIR), token.username,
               token.password, settings.SOJOBO_API_DIR, settings.REDIS_HOST, settings.REDIS_PORT,
               controller, model, credentials])
        code, response = 202, "Model is being deployed"
    else:
        code, response = 404, "Credentials {} not found!".format(credentials)
    return code, response


async def delete_model(token, controller, model):
    if datastore.check_model_state(controller.c_name, model.m_name) != 'error':
        async with controller.connect(token) as juju:
            await juju.destroy_models(model.m_uuid)
        datastore.delete_model(controller.c_name, model.m_name)
        return "Model {} is being deleted".format(model.m_name)
    else:
        return "Model {} is in errorstate".format(model.m_name)
#####################################################################################
# Machines FUNCTIONS
#####################################################################################
async def get_machines_info(token, model):
    result = {}
    async with model.connect(token) as juju:
        for machine, data in juju.state.state.get('machine', {}).items():
            try:
                if data[0]['agent-status']['current'] == 'error' and data[0]['addresses'] is None:
                    result[machine] = {'name': machine, 'Error': data[0]['agent-status']['message']}
                if data[0] is None:
                    result[machine] = {'name': machine, 'instance-id': 'Unknown', 'ip': 'Unknown',
                                       'series': 'Unknown', 'containers': 'Unknown',
                                       'hardware-characteristics' : 'Unknown'}
                if 'lxd' in machine:
                    result[machine.split('/')[0]].get('containers', []).append({
                        'name': machine, 'instance-id': data[0]['instance-id'],
                        'ip': await get_machine_ip(data[0]), 'series': data[0]['series']
                    })
                else:
                    result[machine] = {
                        'name': machine,
                        'instance-id': data[0]['instance-id'],
                        'ip': await get_machine_ip(data[0]),
                        'series': data[0]['series'],
                        'hardware-characteristics': data[0]['hardware-characteristics']
                    }
            except KeyError:
                result[machine] = {'name': machine, 'instance-id': 'Unknown', 'ip': 'Unknown', 'series': 'Unknown',
                                   'containers': 'Unknown', 'hardware-characteristics' : 'Unknown'}
    return [info for info in result.values()]


async def get_machine_info(token, model, machine):
    try:
        async with model.connect(token) as juju:
            data = juju.state.state['machine']
        machine_data = data[machine][0]
        if machine_data['agent-status']['current'] == 'error' and machine_data['addresses'] is None:
            result = {'name': machine, 'Error': machine_data['agent-status']['message']}
            return result
        if machine_data is None:
            result = {'name': machine, 'instance-id': 'Unknown', 'ip': 'Unknown', 'series': 'Unknown', 'containers': 'Unknown', 'hardware-characteristics' : 'unknown'}
            return result
        containers = []
        if not 'lxd' in machine:
            lxd = []
            for key in data.keys():
                if key.startswith('{}/lxd'.format(machine)):
                    lxd.append(key)
            if lxd != []:
                for cont in lxd:
                    cont_data = data[cont][0]
                    ip = await get_machine_ip(cont_data)
                    containers.append({'name': cont, 'instance-id': cont_data['instance-id'], 'ip': ip, 'series': cont_data['series']})
            mach_ip = await get_machine_ip(machine_data)
            result = {'name': machine, 'instance-id': machine_data['instance-id'], 'ip': mach_ip, 'series': machine_data['series'], 'hardware-characteristics' : machine_data['hardware-characteristics'], 'containers': containers}
        else:
            mach_ip = await get_machine_ip(machine_data)
            result = {'name': machine, 'instance-id': machine_data['instance-id'], 'ip': mach_ip, 'series': machine_data['series'], 'hardware-characteristics' : machine_data['hardware-characteristics']}
    except KeyError:
        result = {'name': machine, 'instance-id': 'Unknown', 'ip': 'Unknown', 'series': 'Unknown', 'containers': 'Unknown', 'hardware-characteristics' : 'unknown'}
    return result


async def get_machine_ip(machine_data):
    mach_ips = {'internal_ip' : 'unknown', 'external_ip' : 'unknown'}
    if machine_data['addresses'] is None:
        return mach_ips
    for machine in machine_data['addresses']:
        if machine['scope'] == 'public':
            mach_ips['external_ip'] = machine['value']
        elif machine['scope'] == 'local-cloud':
            mach_ips['internal_ip'] = machine['value']
    return mach_ips


async def add_machine(token, model, ser=None, cont=None):
    async with model.connect(token) as juju:
        await juju.add_machine(series=ser, constraints=cont)


async def machine_exists(token, model, machine):
    async with model.connect(token) as juju:
        return machine in juju.state.state.get('machine', {}).keys()


async def remove_machine(token, controller, model, machine):
    Popen(["python3.6", "{}/scripts/remove_machine.py".format(settings.SOJOBO_API_DIR), token.username,
           token.password, settings.SOJOBO_API_DIR, settings.REDIS_HOST, settings.REDIS_PORT,
           controller.c_name, model.m_name, machine])
#####################################################################################
# APPLICATION FUNCTIONS
#####################################################################################
async def app_exists(token, controller, model, app_name):
    model_info = await get_model_info(token, controller, model)
    for app in model_info['applications']:
        if app['name'] == app_name:
            return True
    return False


async def add_bundle(token, controller, model, bundle):
    Popen(["python3.6", "{}/scripts/bundle_deployment.py".format(settings.SOJOBO_API_DIR),
           token.username, token.password, settings.SOJOBO_API_DIR, controller, model,
           str(bundle), settings.REDIS_HOST, settings.REDIS_PORT])


async def deploy_app(token, model, app_name, name=None, ser=None, tar=None, con=None, num_of_units=1):
    async with model.connect(token) as juju:
        try:
            await juju.deploy(app_name, application_name=name, series=ser, to=tar, config=con, num_units=num_of_units)
        except JujuError as e:
            if e == 'subordinate application must be deployed without units':
                await juju.deploy(app_name, application_name=name, series=ser, to=tar, config=con, num_units=0)


async def check_if_exposed(token, model, app_name):
    app_info = await get_application_info(token, model, app_name)
    return app_info['exposed']


async def expose_app(token, model, app_name):
    async with model.connect(token):
        app = await get_application_entity(token, model, app_name)
        await app.expose()


async def unexpose_app(token, model, app_name):
    async with model.connect(token):
        app = await get_application_entity(token, model, app_name)
        await app.unexpose()


async def get_application_entity(token, model, app_name):
    async with model.connect(token) as juju:
        for app in juju.state.applications.items():
            if app[0] == app_name:
                return app[1]


async def remove_app(token, model, app_name):
    async with model.connect(token):
        app = await get_application_entity(token, model, app_name)
        if app is not None:
            await app.remove()


async def get_application_info(token, model, applic):
    for app in await get_applications_info(token, model):
        if app['name'] == applic:
            return app


async def get_unit_info(token, model, application, unitnumber):
    for u in await get_units_info(token, model, application):
        if u['name'] == '{}/{}'.format(application, unitnumber):
            return u
    return {}


async def add_unit(token, controller, model, app_name, amount, target):
    Popen(["python3.6", "{}/scripts/add_unit.py".format(settings.SOJOBO_API_DIR), token.username,
           token.password, settings.SOJOBO_API_DIR, settings.REDIS_HOST, settings.REDIS_PORT,
           controller.c_name, model.m_name, app_name, str(amount), target])


async def remove_unit(token, model, application, unit_number):
    async with model.connect(token):
        app = await get_application_entity(token, model, application)
        unit = '{}/{}'.format(application, unit_number)
        await app.destroy_unit(unit)


async def get_unit_ports(unit):
    ports = []
    for port in unit['ports']:
        ports.append(port)
    return ports


async def get_relations_info(token, model):
    data = await get_applications_info(token, model)
    return [{'name': a['name'], 'relations': a['relations']} for a in data]


async def add_relation(token, model, app1, app2):
    async with model.connect(token) as juju:
        await juju.add_relation(app1, app2)


async def remove_relation(token, model, app1, app2):
    async with model.connect(token) as juju:
        data = juju.state.state
        application = await get_application_entity(token, model, app1)
        if app1 == app2:
            for relation in data['relation'].items():
                keys = relation[1][0]['key'].split(':')
                await application.destroy_relation(keys[1], '{}:{}'.format(keys[0], keys[1]))
        else:
            for relation in data['relation'].items():
                keys = relation[1][0]['key'].split(' ')
                if len(keys) > 1:
                    if keys[0].startswith(app1):
                        await application.destroy_relation(keys[0].split(':')[1], keys[1])
                    elif keys[1].startswith(app1):
                        await application.destroy_relation(keys[1].split(':')[1], keys[0])


async def set_application_config(token, mod, app_name, config):
    async with mod.connect(token):
        app = await get_application_entity(token, mod, app_name)
        await app.set_config(config)


async def get_application_config(token, mod, app_name):
    async with mod.connect(token):
        app = await get_application_entity(token, mod, app_name)
        return await app.get_config()
###############################################################################
# USER FUNCTIONS
###############################################################################
async def create_user(token, username, password):
    datastore.create_user(username)
    for con in await get_all_controllers():
        controller = Controller_Connection(token, con)
        async with controller.connect(token) as juju:  #pylint: disable=E1701
            await juju.add_user(username, password)
            await juju.grant(username)
            datastore.add_user_to_controller(con, username, 'login')


async def delete_user(token, username):
    for con in await get_all_controllers():
        controller = Controller_Connection(token, con)
        async with controller.connect(token) as juju:  #pylint: disable=E1701
            await juju.disable_user(username)
        datastore.remove_user_from_controller(con, username)
    datastore.disable_user(username)


async def enable_user(token, username):
    for con in await get_all_controllers():
        controller = Controller_Connection(token, con)
        async with controller.connect(token) as juju:  #pylint: disable=E1701
            await juju.enable_user(username)
        datastore.add_user_to_controller(controller, username, 'login')
    datastore.enable_user_con(controller, username)


async def change_user_password(token, username, password):
    for con in await get_all_controllers():
        controller = Controller_Connection(token, con)
        async with controller.connect(token) as juju:  #pylint: disable=E1701
            await juju.change_user_password(username, password)


async def add_ssh_key_user(user, ssh_key):
    Popen([
        "python3.6",
        "{}/scripts/add_ssh_key.py".format(settings.SOJOBO_API_DIR),
        settings.JUJU_ADMIN_USER,
        settings.JUJU_ADMIN_PASSWORD,
        settings.SOJOBO_API_DIR,
        ssh_key, settings.REDIS_HOST, settings.REDIS_PORT, user])


async def remove_ssh_key_user(user, ssh_key):
    Popen([
        "python3.6",
        "{}/scripts/remove_ssh_key.py".format(settings.SOJOBO_API_DIR),
        settings.JUJU_ADMIN_USER,
        settings.JUJU_ADMIN_PASSWORD,
        settings.SOJOBO_API_DIR,
        ssh_key, settings.REDIS_HOST, settings.REDIS_PORT, user])


async def get_users_controller(controller):
    cont_info = datastore.get_controller(controller)
    return cont_info['users']


async def get_users_model(token, controller, model):
    if model.m_access == 'admin' or model.m_access == 'write':
        users = datastore.get_users_model(controller.c_name, model.m_name)
    elif model.m_access == 'read':
        users = [{'name': token.username, 'access': model.m_access}]
    else:
        users = None
    return users


async def get_credentials(user):
    return datastore.get_credentials(user)


async def add_credential(user, c_type, cred_name, credential):
    result_cred = await generate_cred_file(c_type, cred_name, credential)
    Popen(["python3.6", "{}/scripts/add_credential.py".format(settings.SOJOBO_API_DIR), user,
           settings.SOJOBO_API_DIR, str(result_cred), settings.REDIS_HOST, settings.REDIS_PORT])


async def remove_credential(user, cred_name):
    Popen(["python3.6", "{}/scripts/remove_credential.py".format(settings.SOJOBO_API_DIR), user,
           settings.SOJOBO_API_DIR, cred_name, settings.REDIS_HOST, settings.REDIS_PORT])


async def add_user_to_controller(token, controller, user, access):
    Popen(["python3.6", "{}/scripts/set_controller_access.py".format(settings.SOJOBO_API_DIR),
           token.username, token.password, settings.SOJOBO_API_DIR,
           settings.REDIS_HOST, settings.REDIS_PORT, user, access, controller.c_name])


async def remove_user_from_controller(token, con, user):
    await controller_revoke(token, con, user)
    datastore.set_controller_access(con.c_name, user, 'login')
    datastore.remove_models_access(con.c_name, user)


async def controller_grant(token, controller, username, access):
    async with controller(token) as juju:
        await juju.grant(username, acl=access)


async def controller_revoke(token, controller, username):
    async with controller(token) as juju:
        await juju.revoke(username)


async def add_user_to_model(token, controller, model, user, access):
    Popen(["python3.6", "{}/scripts/set_model_access.py".format(settings.SOJOBO_API_DIR), token.username,
           token.password, settings.SOJOBO_API_DIR, settings.REDIS_HOST, settings.REDIS_PORT,
           user, access, controller.c_name, model.m_name])


async def model_grant(token, model, username, access):
    async with model.connect(token) as juju:
        await juju.grant(username, acl=access)


async def remove_user_from_model(token, controller, model, username):
    async with model.connect(token) as juju:
        await juju.revoke(username)
    datastore.remove_model(controller.c_name, model.m_name, username)


async def user_exists(username):
    return username in await get_all_users()


#libjuju: geen andere methode om users op te vragen atm
async def get_all_users():
    return datastore.get_all_users()


async def get_users_info(token):
    if token.is_admin:
        result = []
        for user in await get_all_users():
            u_info = await get_user_info(user)
            if u_info['active']:
                result.append(u_info)
        return result
    else:
        return datastore.get_user(token.username)


async def get_user_info(username):
    return datastore.get_user(username)


async def get_controllers_access(usr):
    user = await get_user_info(usr)
    return user['controllers']


async def get_ucontroller_access(controller, username):
    access = await get_controllers_access(username)
    for acc in access:
        if list(acc.keys())[0] == controller.c_name:
            return acc


async def get_models_access(controller, name):
    return datastore.get_models_access(controller.c_name, name)
#########################
# extra Acces checks
#########################
def c_access_exists(access):
    return access in ['login', 'add-model', 'superuser']


def m_access_exists(access):
    return access in ['read', 'write', 'admin']


def check_access(access):
    acc = access.lower()
    if c_access_exists(acc) or m_access_exists(acc):
        return acc
    else:
        error = errors.invalid_access('access')
        abort(error[0], error[1])


async def check_same_access(user, new_access, controller, model=None):
    if model is None:
        old_acc = await get_ucontroller_access(controller, user)
        return old_acc == new_access
    else:
        old_acc = await get_model_access(model, controller, user)
        return old_acc == new_access
