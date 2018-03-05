#!/usr/bin/python3
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
# pylint: disable=c0111,c0301,c0325,c0103,r0913,r0902,e0401,C0302,e0611
import asyncio
from importlib import import_module
from random import randint
import os
import re
import base64
from subprocess import check_output, check_call, Popen
import json
import hashlib
from flask import abort, Response
from juju import tag
from juju.client import client
from juju.controller import Controller
from juju.errors import JujuAPIError, JujuError
from juju.model import Model
from sojobo_api.api import w_errors as errors, w_datastore as datastore
from sojobo_api import settings


################################################################################
# TENGU FUNCTIONS
################################################################################
def get_controller_types():
    """Returns the types of the controllers (google, aws, etc.). This depends on
    which subordinates (f.e. controller_google) are connected to the sojobo-api charm.
    Each controller subordinate creates a file in the controllers dir."""
    types = {}
    for f_path in os.listdir('{}/controllers'.format(settings.SOJOBO_API_DIR)):
        # TODO: Why the .pyc check?
        if 'controller_' in f_path and '.pyc' not in f_path:
            name = f_path.split('.')[0]
            types[name.split('_')[1]] = import_module('sojobo_api.controllers.{}'.format(name))
    return types


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


def check_input(data, input_type):
    regex_dict = {"controller":{"regex":"^(?!-).*^\S+$", "e_message": "Controller name can not start with a hyphen and can not contain spaces!"},
                  "credential":{"regex":"^[0-9a-zA-Z]([0-9a-zA-Z.-]*[0-9a-zA-Z])$", "e_message": "Credentials may only contain letters, digits and hyphens but can not start with a hyphen"},
                  "username":{"regex":"^[0-9a-zA-Z]([0-9a-zA-Z.-]*[0-9a-zA-Z])$", "e_message": "Username may only contain letters, digits and hyphens but can not start with a hyphen"},
                  "model":{"regex":"^[0-9a-z]([0-9a-z.-]*[0-9a-z])$", "e_message": "model names may only contain lowercase letters, digits and hyphens"}}
    if input_type in regex_dict:
        pattern = re.compile(regex_dict[input_type]['regex'])
        if pattern.match(data):
            return True, data
        else:
            return False, regex_dict[input_type]['e_message']


def check_constraints(data):
    cons = ['mem', 'arch', 'cores', 'spaces', 'container', 'root-disk', 'tags', 'cpu-power', 'virt-type']
    for item in data:
        if item in cons:
            if item == 'arch':
                if data[item] in ['amd64', 'arm', 'i386', 'arm64', 'ppc64el']:
                    pass
                else:
                    error = errors.invalid_option(data[item])
                    abort(error[0], error[1])
            else:
                pass
        else:
            error = errors.invalid_option(item)
            abort(error[0], error[1])


async def authenticate(api_key, auth, data, controller=None, model=None):
    error = errors.unauthorized()
    if api_key == settings.API_KEY:
        if not controller and not model:
            if check_if_admin(auth):
                return data
            elif len(datastore.get_all_controllers()) == 0:
                abort(error[0], error[1])
            else:
                await connect_to_random_controller(data)
                return data
        try:
            check_controller_state(data)
            check_user_state(data)
            if data['c_access']:
                if controller and not model:
                    controller_connection = Controller()
                    await controller_connection.connect(endpoint=data['controller']['endpoints'][0], username=auth.username, password=auth.password, cacert=data['controller']['ca_cert'])
                    return controller_connection
                elif model:
                    model_connection = Model()
                    await model_connection.connect(endpoint=data['controller']['endpoints'][0], uuid=data['model']['uuid'], username=auth.username, password=auth.password, cacert=data['controller']['ca_cert'])
                    return model_connection
            elif data['controller']['state'] == 'ready':
                await connect_to_random_controller(data)
                add_user_to_controllers(data, auth.username, auth.password)
                abort(501, 'User {} is being added to the {} environment'.format(data['controller']['name'], data['user']['name']))
        except JujuAPIError:
            abort(error[0], error[1])
    else:
        abort(error[0], error[1])


def check_if_admin(auth):
    return auth.username == settings.JUJU_ADMIN_USER and auth.password == settings.JUJU_ADMIN_PASSWORD


async def connect_to_random_controller(data):
    error = errors.unauthorized()
    try:
        ready_controllers = datastore.get_all_ready_controllers()
        if len(read_controllers) == 0:
            abort(400,'Please wait untill your first environment is set up!')
        else:
            con = read_controllers[randint(0, len(controllers) - 1)]
            controller_connection = Controller()
            await controller_connection.connect(con['endpoints'][0], auth.username, auth.password, con['ca_cert'])
            await controller_connection.disconnect()
    except JujuAPIError:
        abort(error[0], error[1])


def check_user_state(data):
    if data['user']:
        if data['user']['state'] == 'pending':
            abort(403, "The user is not ready yet to perform this action. Please wait untill the user is created!")
        elif data['user']['state'] != 'ready':
            abort(403, "The user is being removed and not able to perform this action anymore!")

def authorize(connection_info, resource, method, self_user=None):
    """Checks if a user is authorized to perform a certain http method on
    a certain resource. F.e. Is the user allowed to create a model?

    :param connection_info: Contains the controller and/or model access of the
    user that is trying to authorize.

    :param resource: The resource that the user tries to perform an action on.

    :param method: The HTTP method (get, put, post, del)

    :param self_user: Calls like changing the password of a user can be done
    by an admin OR the user himself. If this is the case then 'self_user' must
    be the user that is used in the call."""
    # Check if it is controller or model connection info.
    if self_user == connection_info["user"]["username"]:
        return True
    elif "m_access" in connection_info:
        return w_permissions.m_authorize(connection_info, resource, method)
    elif "c_access" in connection_info:
        return w_permissions.c_authorize(connection_info, resource, method)
    else:
        return connection_info["user"]["username"] == "tengu_admin"


def get_connection_info(username, c_name=None, m_name=None):
    if c_name and m_name:
        m_key = construct_model_key(c_name, m_name)
        return datastore.get_model_connection_info(username, c_name, m_key)
    elif c_name and not m_name:
        return datastore.get_controller_connection_info(username, c_name)
    else:
        return {'user': datastore.get_user_info(username)}


###############################################################################
# CONTROLLER FUNCTIONS
###############################################################################
def cloud_supports_series(controller_connection, series):
    if series is None:
        return True
    else:
        return series in get_controller_types()[controller_connection.c_type].get_supported_series()


def check_c_type(c_type):
    if c_type.lower() in get_controller_types().keys():
        return c_type.lower()
    else:
        error = errors.invalid_controller(c_type)
        abort(error[0], error[1])


def create_controller(token, data):
    c_type = check_c_type(data['type'])
    valid, name = check_input(data['controller'], 'controller')
    if not valid:
        abort(400, error)
    if controller_exists(name):
        ers = errors.already_exists('controller')
        abort(ers[0], ers[1])
    for controller in get_all_controllers():
        if controller['state'] == 'accepted':
            return 503, 'An environment is already being created'
    credential = get_credential(token['user']['name'], data['credential'])
    if not credential['state'] == 'ready':
        abort(503, 'The Credential {} is not ready yet.'.format(credential['name']))
    datastore.create_controller(name, c_type, data['region'], data['credential'])
    if token['user']['name'] == settings.JUJU_ADMIN_USER:
        datastore.add_user_to_controller(name, token['user']['name'], 'tengu_admin')
    else:
        datastore.add_user_to_controller(name, token['user']['name'], 'company_admin')
    return get_controller_types()[c_type].create_controller(name, data)


def delete_controller(con):
    Popen(["python3", "{}/scripts/remove_controller.py".format(settings.SOJOBO_API_DIR),
           con.c_name, con.c_type])

def get_supported_regions(c_type):
    return get_controller_types()[c_type].get_supported_regions()

def get_all_controllers():
    return datastore.get_all_controllers()

def get_keys_controllers():
    return datastore.get_keys_controllers()


def controller_exists(c_name):
    return datastore.controller_exists(c_name)


def get_controller_access(con, username):
    return datastore.get_controller_access(con.c_name, username)


def get_controller_info(token, controller):
    if controller.c_access is not None:
        con_info = datastore.get_controller_info(controller.c_name)
        if con_info['state'] == 'ready':
            con_info['models'] = get_models_info(token, controller)
    else:
        con_info = None
    return con_info


###############################################################################
# MODEL FUNCTIONS
###############################################################################


def construct_model_key(c_name, m_name):
    key_string = c_name + "_" + m_name
    # Must encode 'key_string' because base64 takes 8-bit binary byte data.
    m_key = base64.b64encode(key_string.encode())
    # To return a string you must decode the binary data.
    return m_key.decode()


def get_all_models(controller):
    return datastore.get_all_models(controller.c_name)


def get_model_uuid(controller, model):
    for mod in get_all_models(controller):
        if mod['name'] == model.m_name:
            return mod['uuid']

def get_model_credential(controller, model):
    for mod in get_all_models(controller):
        if mod['name'] == model.m_name:
            return mod['credential']


def get_model_access(model, controller, username):
    return datastore.get_model_access(controller, model, username) if not None else "None"


def get_models_info(token, controller):
    result = []
    models = get_all_models(controller)
    for mod in models:
        print(mod, datastore.get_model_access(controller.c_name, mod, token.username))
        if datastore.get_model_access(controller.c_name, mod['name'], token.username) in ['read', 'write', 'admin']:
            result.append(mod)
    return result


async def get_model_info(token, controller, model):
    state = datastore.get_model_state(model.m_key)
    if state == 'ready':
        async with model.connect(token):
            users = get_users_model(token, controller, model)
            applications = await get_applications_info(token, model)
            machines = await get_machines_info(token, model)
            gui = await get_gui_url(controller, model)
            credentials = {'cloud': controller.c_type, 'credential-name': get_model_credential(controller, model)}
        return {'name': model.m_name, 'users': users,
                'applications': applications, 'machines': machines, 'juju-gui-url' : gui,
                'state': datastore.get_model_state(model.m_key), 'credentials' : credentials}
    elif state == 'accepted' or state == 'error':
        return {'name': model.m_name, 'state': state, 'users' : {"user" : token.username, "access" : "admin"}}
    else:
        return {}


async def get_ssh_keys(token, model):
    async with model.connect(token) as juju:
        res = await juju.get_ssh_key(raw_ssh=True)
    data = res.serialize()['results'][0].serialize()['result']
    if data is None:
        return []
    else:
        return data


def get_ssh_keys_user(username):
    return datastore.get_ssh_keys(username)


async def get_applications_info(token, model):
    result = []
    async with model.connect(token) as juju:
        for data in juju.state.state.get('application', {}).values():
            res = {'name': data[0]['name'], 'relations': [], 'charm': data[0]['charm-url'], 'exposed': data[0]['exposed'],
                   'state': data[0]['status']}
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
            ports = get_unit_ports(u)
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


async def create_model(connection, authentication, m_name, cred_name, c_name):
    """Creates model in database and then in JuJu (background script)."""
    # Construct a key for the model using the controller name and model name.
    key_string = c_name + "_" + m_name
    m_key = construct_model_key(c_name, m_name)
    if not datastore.model_exists(m_key):
        if cred_name in datastore.get_credential_keys(authentication.username):
            # Create the model in ArangoDB. Add model key to controller and
            # set the model access level of the user.
            new_model = datastore.create_model(m_key, m_name, state='deploying')
            # TODO: Maybe put these 3 datastore methods in one so you do not have
            # to create a connection with ArangoDB each time.
            datastore.add_model_to_controller(c_name, m_key)
            datastore.set_model_state(m_key, 'accepted')
            datastore.set_model_access(m_key, authentication.username, 'admin')

            # Run the background script, this creates the model in JuJu.
            Popen(["python3", "{}/scripts/add_model.py".format(settings.SOJOBO_API_DIR),
                    c_name, m_key, m_name, authentication.username, authentication.password, cred_name])

            return 202, "Model is being deployed."
        else:
            return 404, "Credentials {} not found!".format(cred_name)
    else:
        return errors.already_exists('model')[0], errors.already_exists('model')[1]




def check_model_state(m_key, required_states):
    """Checks if a model its state is one of the required states. Certain API calls
    can only succeed if the model is in a certain state. F.e. the call to deploy
    a bundle requires that the model is 'ready' or else a deployment will fail.
    The call to delete a model requires that the model is in 'error' or 'ready' state."""
    state = datastore.get_model_state(m_key)
    if state in required_states:
        return state


# TODO: Functie die bij iedere POST die iets verandert aan een model checkt
# of het model er klaar voor is en een gepast bericht teruggeeft. Maak gebruik van
# abort zoals in authorize. Bundle deployment, applicatie toevoegen, user access
# veranderen, machines. "Model access aangepast voor dit, dit en dit model maar voor dit
# model nog niet"


async def delete_model(token, controller, model):
    async with controller.connect(token) as juju:
        await juju.destroy_models(model.m_uuid)
    datastore.delete_model(controller.c_name, model.m_key)
    return "Model {} is being deleted".format(model.m_name)
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
                        'ip': get_machine_ip(data[0]), 'series': data[0]['series']
                    })
                else:
                    result[machine] = {
                        'name': machine,
                        'instance-id': data[0]['instance-id'],
                        'ip': get_machine_ip(data[0]),
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
                    ip = get_machine_ip(cont_data)
                    containers.append({'name': cont, 'instance-id': cont_data['instance-id'], 'ip': ip, 'series': cont_data['series']})
            mach_ip = get_machine_ip(machine_data)
            result = {'name': machine, 'instance-id': machine_data['instance-id'], 'ip': mach_ip, 'series': machine_data['series'], 'hardware-characteristics' : machine_data['hardware-characteristics'], 'containers': containers}
        else:
            mach_ip = get_machine_ip(machine_data)
            result = {'name': machine, 'instance-id': machine_data['instance-id'], 'ip': mach_ip, 'series': machine_data['series'], 'hardware-characteristics' : machine_data['hardware-characteristics']}
    except KeyError:
        result = {'name': machine, 'instance-id': 'Unknown', 'ip': 'Unknown', 'series': 'Unknown', 'containers': 'Unknown', 'hardware-characteristics' : 'unknown'}
    return result


def get_machine_ip(machine_data):
    mach_ips = {'internal_ip' : 'unknown', 'external_ip' : 'unknown'}
    if machine_data['addresses'] is None:
        return mach_ips
    for machine in machine_data['addresses']:
        if machine['scope'] == 'public':
            mach_ips['external_ip'] = machine['value']
        elif machine['scope'] == 'local-cloud':
            mach_ips['internal_ip'] = machine['value']
    return mach_ips


async def add_machine(token, model, ser=None, cont=None, spec=None):
    async with model.connect(token) as juju:
        await juju.add_machine(series=ser, constraints=cont, spec=spec)


async def machine_exists(token, model, machine):
    async with model.connect(token) as juju:
        return machine in juju.state.state.get('machine', {}).keys()


def remove_machine(token, controller, model, machine):
    Popen(["python3", "{}/scripts/remove_machine.py".format(settings.SOJOBO_API_DIR), token.username,
           token.password, settings.SOJOBO_API_DIR, controller.c_name, model.m_name, machine])


#####################################################################################
# APPLICATION FUNCTIONS
#####################################################################################


async def app_exists(token, controller, model, app_name):
    model_info = await get_model_info(token, controller, model)
    for app in model_info['applications']:
        if app['name'] == app_name:
            return True
    return False


def add_bundle(token, controller, model, bundle):
    Popen(["python3", "{}/scripts/bundle_deployment.py".format(settings.SOJOBO_API_DIR),
           token.username, token.password, settings.SOJOBO_API_DIR, controller, model,
           str(bundle)])


async def deploy_app(token, con, model, app_name, data):
    ser = data.get('series', None)
    if(cloud_supports_series(con, ser)):
        conf = data.get('config', None)
        machine = data.get('target', None)
        if machine and not machine_exists(token, model, machine):
            error = errors.does_not_exist(machine)
            abort(error[0], error[1])
        units = data.get('units', "1")
        async with model.connect(token) as juju:
            try:
                await juju.deploy(app_name, application_name=app_name, series=ser, to=machine, config=conf, num_units=int(units))
            except JujuError as e:
                if e == 'subordinate application must be deployed without units':
                    await juju.deploy(app_name, application_name=app_name, series=ser, config=conf, num_units=0)
    else:
        error = errors.invalid_option(data)
        abort(error[0], error[1])



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


def add_unit(token, controller, model, app_name, amount, target):
    Popen(["python3", "{}/scripts/add_unit.py".format(settings.SOJOBO_API_DIR), token.username,
           token.password, settings.SOJOBO_API_DIR, controller.c_name, model.m_name,
           app_name, str(amount), target])


async def remove_unit(token, model, application, unit_number):
    async with model.connect(token):
        app = await get_application_entity(token, model, application)
        unit = '{}/{}'.format(application, unit_number)
        await app.destroy_unit(unit)


def get_unit_ports(unit):
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


async def set_application_config(token, model, app_name, config):
    async with model.connect(token):
        app = await get_application_entity(token, model, app_name)
        for con in config:
            config['con'] = str(config['con'])
        await app.set_config(config)


async def get_application_config(token, model, app_name):
    async with model.connect(token):
        app = await get_application_entity(token, model, app_name)
        try:
            return await app.get_config()
        except AttributeError:
            return errors.does_not_exist("application" + str(app_name))

###############################################################################
# USER FUNCTIONS
###############################################################################
def create_user(username, password):
    Popen(["python3", "{}/scripts/add_user.py".format(settings.SOJOBO_API_DIR), username, password])


def delete_user(username):
    Popen(["python3", "{}/scripts/delete_user.py".format(settings.SOJOBO_API_DIR), username])

def add_user_to_controllers(data, username, password):
    Popen(["python3", "{}/scripts/add_user_to_controllers.py".format(settings.SOJOBO_API_DIR),data, username, password])


async def change_user_password(token, username, password):
    for con in get_keys_controllers():
        controller = Controller_Connection(token, con)
        async with controller.connect(token) as juju:  #pylint: disable=E1701
            await juju.change_user_password(username, password)


def update_ssh_keys_user(user, ssh_keys):
    Popen([
        "python3",
        "{}/scripts/update_ssh_keys.py".format(settings.SOJOBO_API_DIR),
        str(ssh_keys), user, settings.SOJOBO_API_DIR])


def get_users_controller(controller):
    return datastore.get_users_controller(controller)


def get_users_model(token, controller, model):
    if model.m_access == 'admin' or model.m_access == 'write':
        aql_data = datastore.get_users_model(model.m_key)
        users = [user for user in aql_data]
    elif model.m_access == 'read':
        users = [{'name': token.username, 'access': model.m_access}]
    else:
        users = None
    return users


def get_credentials(user):
    return datastore.get_credentials(user)


def get_credential(user, credential):
    return datastore.get_credential(user, credential)



def add_credential(user, data):
    try:
        return get_controller_types()[data['type']].add_credential(user, data)
    except NotImplementedError as e:
        return 400, "This type of controller does not need credentials"


async def update_cloud(controller, cloud, credential, username):
    credential_name = 't{}'.format(hashlib.md5(credential.encode('utf')).hexdigest())
    cloud_facade = client.CloudFacade.from_connection(controller.connection)
    cred = get_controller_types()[cloud].generate_cred_file(credential_name, credential)
    cloud_cred = client.UpdateCloudCredential(
        client.CloudCredential(cred['key'], cred['type']),
        tag.credential(cloud, username, credential_name)
    )
    await cloud_facade.UpdateCredentials([cloud_cred])


def remove_credential(user, cred_name):
    Popen(["python3", "{}/scripts/remove_credential.py".format(settings.SOJOBO_API_DIR), user, cred_name, settings.SOJOBO_API_DIR])


def credential_exists(user, credential):
    for cred in get_credentials(user):
        if cred['name'] == credential:
            if not cred['state'] == 'ready':
                raise Exception('The Credential {} is not ready yet.'.format(cred_name))
            return True
    return False

def grant_user_to_controller(token, controller, user, access):
    Popen(["python3", "{}/scripts/set_controller_access.py".format(settings.SOJOBO_API_DIR),
           controller.c_name, access, settings.SOJOBO_API_DIR, user])


async def controller_grant(token, controller, username, access):
    async with controller(token) as juju:
        await juju.grant(username, acl=access)


async def controller_revoke(token, controller, username):
    async with controller(token) as juju:
        await juju.revoke(username)


def set_models_access(token, controller, user, accesslist):
    for mod in accesslist:
        m_key = construct_model_key(controller.c_name, mod['name'])
        if datastore.model_exists(m_key):
            if not m_access_exists(mod['access']):
                abort(400, 'Access Level {} is not supported. Change access for model {}'.format(mod['access'], mod['name']))
            else:
                pass
        else:
            abort(404, 'Model {} not found'.format(mod['name']))
    Popen(["python3", "{}/scripts/set_model_access.py".format(settings.SOJOBO_API_DIR), token.username,
           token.password, settings.SOJOBO_API_DIR,
           user, str(accesslist), controller.c_name])


async def model_grant(token, model, username, access):
    async with model.connect(token) as juju:
        await juju.grant(username, acl=access)


def user_exists(username):
    return datastore.user_exists(username)


def get_all_users():
    return datastore.get_all_users()


def get_users_info(data):
    """An admin user is allowed to access info of all other users. Users who
    have no admin rights have only access to info about themselves."""
    if data['name'] == settings.JUJU_ADMIN_USER:
        result = []
        for user in get_all_users():
            u_info = get_user_info(user["name"])
            result.append(u_info)
        return result
    else:
        return datastore.get_user_info(token.username)


def get_user_info(username):
    return datastore.get_user_info(username)


def check_controllers_access(token, user):
    result = []
    for con in get_keys_controllers():
        if datastore.get_controller_access(con, token.username) == 'superuser':
            result.append(get_ucontroller_access(con, user))
    if len(result) > 0:
        return True, result
    else:
        return False, result


def get_controllers_access(usr):
    return datastore.get_controllers_access(usr)


def get_ucontroller_access(controller, username):
    return datastore.get_controller_and_access(controller, username)


def get_models_access(controller, name):
    return datastore.get_models_access(controller.c_name, name)


def check_models_access(token, controller, user):
    result = []
    for mod_acc in get_models_access(controller, token.username):
        if mod_acc['access'] == 'admin':
            result.append(get_model_access(mod_acc['name'], controller, user))
    if len(result) > 0:
        return True, result
    else:
        return False, result


#########################
# extra Acces checks
#########################
def c_access_exists(access):
    return access in ['login', 'add-model', 'superuser']


def m_access_exists(access):
    return access in ['read', 'write', 'admin']


# def check_access(access):
#     acc = access.lower()
#     if c_access_exists(acc) or m_access_exists(acc):
#         return acc
#     else:
#         error = errors.invalid_access('access')
#         abort(error[0], error[1])
