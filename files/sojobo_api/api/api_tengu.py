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
# pylint: disable=c0111,c0301,c0325,w0406,e0401,e0611
import os
import shutil
import tempfile
import zipfile
import sys
import traceback
import logging
import time

from urllib.parse import unquote
from werkzeug.exceptions import HTTPException
from flask import send_file, request, Blueprint, abort

from sojobo_api.api import w_errors as errors, w_juju as juju, w_datastore as datastore
from sojobo_api.api.w_juju import execute_task
from sojobo_api.api.core import w_tengu
from sojobo_api.api.managers import model_manager, controller_manager
from sojobo_api.api.core.authorization import authorize

TENGU = Blueprint('tengu', __name__)
LOGGER = logging.getLogger('api_tengu')
WS_LOGGER = logging.getLogger('websockets.protocol')
LOGGER.setLevel(logging.DEBUG)
WS_LOGGER.setLevel(logging.DEBUG)

def get():
    return TENGU

@TENGU.before_app_first_request
def initialize():
    hdlr = logging.FileHandler('/opt/sojobo_api/log/api_tengu.log')
    hdlr.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    LOGGER.addHandler(hdlr)
    WS_LOGGER.addHandler(hdlr)


@TENGU.route('/controllers', methods=['GET'])
def get_all_controllers():
    try:
        LOGGER.info('/TENGU/controllers [GET] => receiving call')
        auth_data = juju.get_connection_info(request.authorization)
        execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data)
        LOGGER.info('/TENGU/controllers [GET] => Authenticated!')
        if auth_data['company']:
            company = auth_data['company']['name']
        else:
            company = None
        if juju.check_if_admin(request.authorization, company):
            LOGGER.info('/TENGU/controllers [GET] => Succesfully retrieved all controllers!')
            return juju.create_response(200, juju.get_keys_controllers(company))
        else:
            code, response = errors.no_permission()
            LOGGER.info('/TENGU/controllers/ [GET] => No Permission to perform this action!')
            return juju.create_response(code, response)

    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)



@TENGU.route('/controllers', methods=['POST'])
def create_controller():
    try:
        data = request.json
        url = request.url_rule
        LOGGER.info('%s [POST] => receiving call', url)
        auth_data = juju.get_connection_info(request.authorization)
        execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data)
        LOGGER.info('%s [POST] => Authenticated', url)
        if auth_data['company']:
            comp = auth_data['company']['name']
        else:
            comp = None
        if juju.check_if_admin(request.authorization, company=comp):
            if juju.credential_exists(auth_data['user']['name'], data['credential']):
                code, response = juju.create_controller(auth_data, data, request.authorization.username, request.authorization.password, comp)
                LOGGER.info('%s [POST] => Creating Controller %s, check add_controller.log for more details! ', url, data['controller'])
                return juju.create_response(code, response)
            else:
                code, response = 400, 'Credential {} not found for user {}'.format(data['credential'], auth_data['user']['name'])
                return juju.create_response(code, response)
        else:
            code, response = errors.no_permission()
            LOGGER.error('%s [POST] => No Permission to perform action!', url)
            return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)


@TENGU.route('/controllers/<controller>', methods=['GET'])
def get_controller_info(controller):
    try:
        controller = unquote(controller)
        LOGGER.info('/TENGU/controllers/%s [GET] => receiving call', controller)
        auth_data = juju.get_connection_info(request.authorization, c_name=controller)
        connection = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data, controller=controller)
        LOGGER.info('/TENGU/controllers/%s [GET] => Authenticated!', controller)
        if auth_data['company']:
            comp = auth_data['company']['name']
        else:
            comp = None
        if authorize(auth_data, '/controllers/controller', 'get'):
            LOGGER.info('/TENGU/controllers/%s [GET] => Authorized!', controller)
            code, response = 200, juju.get_controller_info(auth_data, comp)
            LOGGER.info('/TENGU/controllers/%s [GET] => Succesfully retrieved controller information!', controller)
            if 'models' in response:
                new_models = []
                for mod in response['models']:
                    if mod != 'controller' and mod != 'default':
                        new_models.append(mod)
                response['models'] = new_models
            return juju.create_response(code, response)
        else:
            code, response = errors.no_permission()
            LOGGER.info('/TENGU/controllers/%s [GET] => No Permission to perform this action!', controller)
            return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)
    finally:
        if 'connection' in locals():
            execute_task(juju.disconnect, connection)



@TENGU.route('/controllers/<controller>', methods=['DELETE'])
def delete_controller(controller):
    try:
        controller = unquote(controller)
        LOGGER.info('/TENGU/controllers/%s [DELETE] => receiving call', controller)
        auth_data = juju.get_connection_info(request.authorization, c_name=controller)
        connection = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data, controller=controller)
        LOGGER.info('/TENGU/controllers/%s [DELETE] => Authenticated!', controller)
        if auth_data['company']:
            comp = auth_data['company']['name']
        else:
            comp = None
        if juju.check_if_admin(request.authorization, company=comp):
            LOGGER.info('/TENGU/controllers/%s [DELETE] => Authorized!', controller)
            LOGGER.info('/TENGU/controllers/%s [DELETE] => Deleting Controller!', controller)
            juju.delete_controller(controller, auth_data['controller']['type'])
            code, response = 202, 'Controller {} is being deleted'.format(controller)
            LOGGER.info('/TENGU/controllers/%s [DELETE] => Succesfully deleted controller!', controller)
            return juju.create_response(code, response)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/TENGU/controllers/%s [DELETE] => No Permission to perform this action!', controller)
            return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)
    finally:
        if 'connection' in locals():
            execute_task(juju.disconnect, connection)


@TENGU.route('/controllers/<controller>/models', methods=['POST'])
def create_model(controller):
    try:
        controller = unquote(controller)
        LOGGER.info('/TENGU/controllers/%s/models [POST] => receiving call', controller)
        data = request.json
        auth_data = juju.get_connection_info(request.authorization, c_name=controller)
        connection = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data, controller=controller)
        LOGGER.info('/TENGU/controllers/%s/models [POST] => Authenticated!', controller)
        if auth_data['company']:
            comp = auth_data['company']['name']
        else:
            comp = None
        if authorize(auth_data, '/controllers/controller/models', 'post'):
            LOGGER.info('/TENGU/controllers/%s/models [POST] => Authorized!', controller)
            cred = data.get('credential', None)
            if not cred:
                cred = auth_data['controller']['default-credential']
            if juju.credential_exists(auth_data['user']['name'], cred):
                credential = juju.get_credential(auth_data['user']['name'], cred)
                if credential["type"] == auth_data['controller']["type"]:
                    credential_name = cred
                    ws_type = None
                    if "workspace_type" in data:
                        ws_type = data['workspace_type']
                        if not datastore.workspace_type_exists(ws_type):
                            code, response = errors.does_not_exist("workspace type {}".format(ws_type))
                            return juju.create_response(code, response)
                    code, response = juju.create_model(request.authorization,
                                                       data['model'],
                                                       credential_name,
                                                       controller,
                                                       comp,
                                                       ws_type)
                    LOGGER.info('/TENGU/controllers/%s/models [POST] => Creating model, check add_model.log for more details', controller)
                    return juju.create_response(code, response)
                else:
                    return juju.create_response(400, 'Credential {} not compatible with controller {}'.format(data['credential'], auth_data['controller']['name']))
            else:
                return juju.create_response(400, 'Credential {} not found for user {}'.format(data['credential'], auth_data['user']['name']))
        else:
            LOGGER.error('/TENGU/controllers/%s/models [POST] => No Permission to perform this action!', controller)
            code, response = errors.no_permission()
            return juju.create_response(code, response)
    except KeyError:
        error_log()
        return juju.create_response(errors.invalid_data()[0], errors.invalid_data()[1])
    except HTTPException:
        raise
    except Exception:
        ers = error_log()
        return juju.create_response(errors.cmd_error(ers)[0], errors.cmd_error(ers)[1])
    finally:
        if 'connection' in locals():
            execute_task(juju.disconnect, connection)

@TENGU.route('/controllers/<controller>/models', methods=['GET'])
def get_models_info(controller):
    try:
        controller = unquote(controller)
        LOGGER.info('/TENGU/controllers/%s/models [GET] => receiving call', controller)
        auth_data = juju.get_connection_info(request.authorization, c_name=controller)
        connection = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data, controller=controller)
        LOGGER.info('/TENGU/controllers/%s/models [GET] => Authenticated!', controller)
        if auth_data['company']:
            comp = auth_data['company']['name']
        else:
            comp = None
        if authorize(auth_data, '/controllers/controller/models', 'get'):
            LOGGER.info('/TENGU/controllers/%s/models [GET] => Authorized!', controller)
            code, response = 200, [m['name'] for m in juju.get_models_access(auth_data["user"]["name"], controller, comp)]
            LOGGER.info('/TENGU/controllers/%s/models [GET] => modelinfo retieved for all models!', controller)
            new_models = []
            for mod in response:
                if mod != 'controller' and mod != 'default':
                    new_models.append(mod)
            response = new_models
            return juju.create_response(code, response)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/TENGU/controllers/%s/models [GET] => No Permission to perform this action!', controller)
            return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)
    finally:
        if 'connection' in locals():
            execute_task(juju.disconnect, connection)

@TENGU.route('/controllers/<controller>/models/<model>', methods=['GET'])
def get_model_info(controller, model):
    try:
        controller = unquote(controller)
        model = unquote(model)
        LOGGER.info('/TENGU/controllers/%s/models/%s [GET] => receiving call', controller, model)
        auth_data = juju.get_connection_info(request.authorization, c_name=controller, m_name=model)
        LOGGER.info('/TENGU/controllers/%s/models/%s [GET] => got connection info', controller, model)
        connection = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data, controller=controller, model=model)
        LOGGER.info('/TENGU/controllers/%s/models/%s [GET] => Authenticated!', controller, model)
        if authorize(auth_data, '/controllers/controller/models/model', 'get'):
            LOGGER.info('/TENGU/controllers/%s/models/%s [GET] => Authorized!', controller, model)
            code, response = 200, execute_task(juju.get_model_info, connection, auth_data)
            LOGGER.info('/TENGU/controllers/%s/models/%s [GET] => model information retrieved!', controller, model)
            return juju.create_response(code, response)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/TENGU/controllers/%s/models/%s [GET] => No Permission to perform this action!', controller, model)
            return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)
    finally:
        if 'connection' in locals():
            execute_task(juju.disconnect, connection)


@TENGU.route('/controllers/<controller>/models/<model>', methods=['POST'])
def add_bundle(controller, model):
    try:
        controller = unquote(controller)
        model = unquote(model)
        LOGGER.info('/TENGU/controllers/%s/models/%s [POST] => receiving call', controller, model)
        data = request.json
        auth_data = juju.get_connection_info(request.authorization, c_name=controller, m_name=model)
        connection = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data, controller=controller, model=model)
        LOGGER.info('/TENGU/controllers/%s/models/%s [POST] => Authenticated!', controller, model)
        if auth_data['company']:
            comp = auth_data['company']['name']
        else:
            comp = None
        if authorize(auth_data, '/controllers/controller/models/model', 'post'):
            LOGGER.info('/TENGU/controllers/%s/models/%s [POST] => Authorized!', controller, model)
            # Check if the model is 'ready' or else a bundle cannot be deployed.
            bundle = data['bundle']
            if 'applications' in bundle:
                bundle['services'] = bundle['applications']
                bundle.pop('applications')
            LOGGER.info('/TENGU/controllers/%s/models/%s [POST] => Bundle is being deployed, check bundle_deployment.log for more information!', controller, model)
            juju.add_bundle(request.authorization.username, request.authorization.password, controller, model, bundle, comp)
            code, response = 202, "Bundle is being deployed"
            return juju.create_response(code, response)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/TENGU/controllers/%s/models/%s [POST] => No Permission to perform action!', controller, model)
            return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)
    finally:
        if 'connection' in locals():
            execute_task(juju.disconnect, connection)


@TENGU.route('/controllers/<controller>/models/<model>', methods=['DELETE'])
def delete_model(controller, model):
    try:
        controller = unquote(controller)
        model = unquote(model)
        LOGGER.info('/TENGU/controllers/%s/models/%s [DELETE] => receiving call', controller, model)
        auth_data = juju.get_connection_info(request.authorization, c_name=controller, m_name=model)
        connection = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data, controller=controller, model=model)
        if auth_data['company']:
            comp = auth_data['company']['name']
        else:
            comp = None
        if authorize(auth_data, '/controllers/controller/models/model', 'del'):
            LOGGER.info('/TENGU/controllers/%s/models/%s [DELETE] => Authorized!', controller, model)
            juju.delete_model(request.authorization.username, request.authorization.password, controller, model, auth_data['model']['_key'], comp)
            code, response = 202, 'Model is being deleted!'
            LOGGER.info('/TENGU/controllers/%s/models/%s [DELETE] => Model is being deleted!', controller, model)
            return juju.create_response(code, response)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/TENGU/controllers/%s/models/%s [DELETE] => No Permission to perform this action!', controller, model)
            return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)
    finally:
        if 'connection' in locals():
            execute_task(juju.disconnect, connection)


@TENGU.route('/controllers/<controller>/models/<model>/applications', methods=['GET'])
def get_applications_info(controller, model):
    try:
        controller = unquote(controller)
        model = unquote(model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications [GET] => receiving call', controller, model)
        auth_data = juju.get_connection_info(request.authorization, c_name=controller, m_name=model)
        connection = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data, controller=controller, model=model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications [GET] => Authenticated!', controller, model)
        if authorize(auth_data, '/controllers/controller/models/model/applications', 'get'):
            LOGGER.info('/TENGU/controllers/%s/models/%s/applications [GET] => Authorized!', controller, model)
            code, response = 200, juju.get_applications_info(connection)
            LOGGER.info('/TENGU/controllers/%s/models/%s/applications [GET] => succesfully retieved applications info!', controller, model)
            return juju.create_response(code, response)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/TENGU/controllers/%s/models/%s/applications [GET] => No Permission to perform this action!', controller, model)
            return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)
    finally:
        if 'connection' in locals():
            execute_task(juju.disconnect, connection)



@TENGU.route('/controllers/<controller>/models/<model>/applications', methods=['POST'])
def add_application(controller, model):
    try:
        controller = unquote(controller)
        model = unquote(model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications [POST] => receiving call', controller, model)
        data = request.json
        auth_data = juju.get_connection_info(request.authorization, c_name=controller, m_name=model)
        connection = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data, controller=controller, model=model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications [POST] => Authenticated!', controller, model)
        if auth_data['company']:
            comp = auth_data['company']['name']
        else:
            comp = None
        if authorize(auth_data, '/controllers/controller/models/model/applications', 'post'):
            LOGGER.info('/TENGU/controllers/%s/models/%s/applications [POST] => Authorized!', controller, model)
            if auth_data['model'] is not None:
                juju.deploy_app(connection, controller, auth_data['model']['_key'], request.authorization.username, request.authorization.password,
                                auth_data['controller']['type'], data.get('units', "1"), data.get('config', ''), data.get('target', None),
                                data.get('application', None), data.get('series', None), comp)
                code, response = 202, 'Application is being deployed!'
                LOGGER.info('/TENGU/controllers/%s/models/%s/applications [POST] => succesfully deployed application!', controller, model)
                return juju.create_response(code, response)
            else:
                code, response = errors.does_not_exist("model " + model)
                return juju.create_response(code, response)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/TENGU/controllers/%s/models/%s/applications [GET] => No Permission to perform this action!', controller, model)
            return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)
    finally:
        if 'connection' in locals():
            execute_task(juju.disconnect, connection)


@TENGU.route('/controllers/<controller>/models/<model>/applications/<application>', methods=['GET'])
def get_application_info(controller, model, application):
    try:
        controller = unquote(controller)
        model = unquote(model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s [GET] => receiving call', controller, model, application)
        auth_data = juju.get_connection_info(request.authorization, c_name=controller, m_name=model)
        connection = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data, controller=controller, model=model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s [GET] => Authenticated!', controller, model, application)
        if authorize(auth_data, '/controllers/controller/models/model/applications/application', 'get'):
            LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s [GET] => authorized!', controller, model, application)
            code, response = 200, juju.get_application_info(connection, application)
            LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s [GET] => Succesfully retrieved application info!', controller, model, application)
            return juju.create_response(code, response)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/TENGU/controllers/%s/models/%s/applications/%s [GET] => No Permission to perform this action!', controller, model, application)
            return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)
    finally:
        if 'connection' in locals():
            execute_task(juju.disconnect, connection)


@TENGU.route('/controllers/<controller>/models/<model>/applications/<application>', methods=['PUT'])
def expose_application(controller, model, application):
    data = request.json
    try:
        controller = unquote(controller)
        model = unquote(model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s [PUT] => receiving call', controller, model, application)
        auth_data = juju.get_connection_info(request.authorization, c_name=controller, m_name=model)
        connection = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data, controller=controller, model=model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s [PUT] => Authenticated!', controller, model, application)
        if authorize(auth_data, '/controllers/controller/models/model/applications/application', 'put'):
            LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s [PUT] => Authorized!', controller, model, application)
            if data['expose']:
                execute_task(juju.expose_app, connection, application)
                LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s [PUT] => Application exposed!', controller, model, application)
                return juju.create_response(202, 'Application is being Exposed')
            else:
                execute_task(juju.unexpose_app, connection, application)
                LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s [PUT] => Application unexposed!', controller, model, application)
                return juju.create_response(202, 'Application is being Unexposed')
        else:
            code, response = errors.no_permission()
            LOGGER.error('/TENGU/controllers/%s/models/%s/applications/%s [PUT] => No Permission to perform this action!', controller, model, application)
            return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)
    finally:
        if 'connection' in locals():
            execute_task(juju.disconnect, connection)


@TENGU.route('/controllers/<controller>/models/<model>/applications/<application>', methods=['DELETE'])
def remove_app(controller, model, application):
    try:
        controller = unquote(controller)
        model = unquote(model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s [DELETE] => receiving call', controller, model, application)
        auth_data = juju.get_connection_info(request.authorization, c_name=controller, m_name=model)
        connection = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data, controller=controller, model=model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s [DELETE] => Authenticated!', controller, model, application)
        if auth_data['company']:
            comp = auth_data['company']['name']
        else:
            comp = None
        if authorize(auth_data, '/controllers/controller/models/model/applications/application', 'del'):
            LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s [DELETE] => Authorized!', controller, model, application)
            juju.remove_app(connection, application, request.authorization.username, request.authorization.password, controller, auth_data['model']['_key'], comp)
            code, response = 202, "The application is being removed"
            LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s [DELETE] => Removing application!', controller, model, application)
            return juju.create_response(code, response)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/TENGU/controllers/%s/models/%s/applications/%s [DELETE] => No Permission to perform this action!', controller, model, application)
            return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)
    finally:
        if 'connection' in locals():
            execute_task(juju.disconnect, connection)

@TENGU.route('/controllers/<controller>/models/<model>/applications/<application>/config', methods=['GET'])
def get_application_config(controller, model, application):
    try:
        controller = unquote(controller)
        model = unquote(model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/config [GET] => receiving call', controller, model, application)
        auth_data = juju.get_connection_info(request.authorization, c_name=controller, m_name=model)
        connection = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data, controller=controller, model=model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/config [GET] => Authenticated!', controller, model, application)
        if authorize(auth_data, '/controllers/controller/models/model/applications/application/config', 'get'):
            LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/config [GET] => Authorized!', controller, model, application)
            code, response = 200, execute_task(juju.get_application_config, connection, application)
            LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/config [GET] => Succesfully retrieved application config!', controller, model, application)
            return juju.create_response(code, response)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/TENGU/controllers/%s/models/%s/applications/%s/config [GET] => No Permission to perform this action!', controller, model, application)
            return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        ers = error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)
    finally:
        if 'connection' in locals():
            execute_task(juju.disconnect, connection)


@TENGU.route('/controllers/<controller>/models/<model>/applications/<application>/config', methods=['PUT'])
def set_application_config(controller, model, application):
    try:
        controller = unquote(controller)
        model = unquote(model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/config [PUT] => receiving call', controller, model, application)
        data = request.json
        auth_data = juju.get_connection_info(request.authorization, c_name=controller, m_name=model)
        connection = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data, controller=controller, model=model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/config [PUT] => Authenticated!', controller, model, application)
        if auth_data['company']:
            comp = auth_data['company']['name']
        else:
            comp = None
        if authorize(auth_data, '/controllers/controller/models/model/applications/application/config', 'put'):
            LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/config [PUT] => Authorized!', controller, model, application)
            config = data.get('config', None)
            if not config:
                return juju.create_response(400, 'Please provide at least 1 config parameter')
            juju.set_application_config(connection, request.authorization.username, request.authorization.password, controller, auth_data['model']['_key'], application, config, comp)
            LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/config [PUT] => Config parameter is being changed!', controller, model, application)
            code, response = 202, "The config parameter is being changed"
            return juju.create_response(code, response)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/TENGU/controllers/%s/models/%s/applications/%s/config [PUT] => No Permission to perform this action!', controller, model, application)
            return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)
    finally:
        if 'connection' in locals():
            execute_task(juju.disconnect, connection)


@TENGU.route('/controllers/<controller>/models/<model>/machines', methods=['GET'])
def get_machines_info(controller, model):
    try:
        controller = unquote(controller)
        model = unquote(model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/machines [GET] => receiving call', controller, model)
        auth_data = juju.get_connection_info(request.authorization, c_name=controller, m_name=model)
        connection = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data, controller=controller, model=model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/machines [GET] => Authenticated!', controller, model)
        if authorize(auth_data, '/controllers/controller/models/model/machines', 'get'):
            LOGGER.info('/TENGU/controllers/%s/models/%s/machines [GET] => Authorized!', controller, model)
            code, response = 200, juju.get_machines_info(connection)
            LOGGER.info('/TENGU/controllers/%s/models/%s/machines [GET] => Succesfully retrieved machine information!', controller, model)
            return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        ers = error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)
    finally:
        if 'connection' in locals():
            execute_task(juju.disconnect, connection)


@TENGU.route('/controllers/<controller>/models/<model>/machines', methods=['POST'])
def add_machine(controller, model):
    try:
        controller = unquote(controller)
        model = unquote(model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/machines [POST] => receiving call', controller, model)
        data = request.json
        auth_data = juju.get_connection_info(request.authorization, c_name=controller, m_name=model)
        connection = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data, controller=controller, model=model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/machines [POST] => Authenticated!', controller, model)
        if auth_data['company']:
            comp = auth_data['company']['name']
        else:
            comp = None
        if authorize(auth_data, '/controllers/controller/models/model/machines', 'post'):
            LOGGER.info('/TENGU/controllers/%s/models/%s/machines [POST] => Authorized!', controller, model)
            constraints = data.get('constraints', None)
            series = data.get('series', None)
            spec = None
            if constraints:
                juju.check_constraints(constraints)
            if 'url' in data and juju.cloud_supports_series(auth_data['controller']['type'], series):
                spec = 'ssh:ubuntu@{}'.format(data['url'])
            if juju.cloud_supports_series(controller, series):
                juju.add_machine(request.authorization.username, request.authorization.password, controller, auth_data['model']['_key'], series, constraints, spec, comp)
                LOGGER.info('/TENGU/controllers/%s/models/%s/machines [POST] => Creating Machine!', controller, model)
                code, response = 202, 'Machine is being deployed!'
                return juju.create_response(code, response)
            else:
                code, response = 400, 'This cloud does not support this version of Ubuntu'
                LOGGER.error('/TENGU/controllers/%s/models/%s/machines [POST] => This cloud does not support this version of Ubuntu!', controller, model)
                return juju.create_response(code, response)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/TENGU/controllers/%s/models/%s/machines [POST] => No Permission to perform this action!', controller, model)
            return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)
    finally:
        if 'connection' in locals():
            execute_task(juju.disconnect, connection)


@TENGU.route('/controllers/<controller>/models/<model>/machines/<machine>', methods=['GET'])
def get_machine_info(controller, model, machine):
    try:
        controller = unquote(controller)
        model = unquote(model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/machines/%s [GET] => receiving call', controller, model, machine)
        auth_data = juju.get_connection_info(request.authorization, c_name=controller, m_name=model)
        connection = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data, controller=controller, model=model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/machines/%s [GET] => Authenticated!', controller, model, machine)
        if authorize(auth_data, '/controllers/controller/models/model/machines/machine', 'get'):
            LOGGER.info('/TENGU/controllers/%s/models/%s/machines/%s [GET] => Authorized!', controller, model, machine)
            code, response = 200, juju.get_machine_info(connection, machine)
            LOGGER.info('/TENGU/controllers/%s/models/%s/machines/%s [GET] => Succesfully retrieved machine information!', controller, model, machine)
            return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)
    finally:
        if 'connection' in locals():
            execute_task(juju.disconnect, connection)



@TENGU.route('/controllers/<controller>/models/<model>/machines/<machine>', methods=['DELETE'])
def remove_machine(controller, model, machine):
    try:
        controller = unquote(controller)
        model = unquote(model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/machines/%s [DELETE] => receiving call', controller, model, machine)
        auth_data = juju.get_connection_info(request.authorization, c_name=controller, m_name=model)
        connection = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data, controller=controller, model=model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/machines/%s [DELETE] => Authenticated!', controller, model, machine)
        if auth_data['company']:
            comp = auth_data['company']['name']
        else:
            comp = None
        if authorize(auth_data, '/controllers/controller/models/model/machines/machine', 'del'):
            LOGGER.info('/TENGU/controllers/%s/models/%s/machines/%s [DELETE] => Authorized!', controller, model, machine)
            juju.remove_machine(connection, request.authorization.username, request.authorization.password, controller, auth_data['model']['_key'], machine, comp)
            code, response = 202, 'Machine being removed'
            LOGGER.info('/TENGU/controllers/%s/models/%s/machines/%s [GET] => Destroying machine, check remove_machine.log for more information!', controller, model, machine)
            return juju.create_response(code, response)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/TENGU/controllers/%s/models/%s/machines/%s [DELETE] => No Permission to perform this action!', controller, model, machine)
            return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        ers = error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)
    finally:
        if 'connection' in locals():
            execute_task(juju.disconnect, connection)


@TENGU.route('/controllers/<controller>/models/<model>/applications/<application>/units', methods=['GET'])
def get_units_info(controller, model, application):
    try:
        controller = unquote(controller)
        model = unquote(model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/units [GET] => receiving call', controller, model, application)
        auth_data = juju.get_connection_info(request.authorization, c_name=controller, m_name=model)
        connection = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data, controller=controller, model=model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/units [GET] => Auhtenticated!', controller, model, application)
        if authorize(auth_data, '/controllers/controller/models/model/applications/application/units', 'get'):
            LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/units [GET] => Authorized!', controller, model, application)
            if juju.app_exists(connection, application):
                code, response = 200, juju.get_units_info(connection, application)
                LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/units [GET] => Succesfully retrieved units info!', controller, model, application)
            else:
                code, response = errors.does_not_exist('application')
                LOGGER.error('/TENGU/controllers/%s/models/%s/applications/%s/units [GET] => Application does not exist!', controller, model, application)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/TENGU/controllers/%s/models/%s/applications/%s/units [GET] => No Permission to perform this action!', controller, model, application)
        return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        ers = error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)
    finally:
        if 'connection' in locals():
            execute_task(juju.disconnect, connection)


@TENGU.route('/controllers/<controller>/models/<model>/applications/<application>/units', methods=['POST'])
def add_unit(controller, model, application):
    try:
        controller = unquote(controller)
        model = unquote(model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/units [POST] => receiving call', controller, model, application)
        data = request.json
        auth_data = juju.get_connection_info(request.authorization, c_name=controller, m_name=model)
        connection = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data, controller=controller, model=model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/units [POST] => Authenticated!', controller, model, application)
        if auth_data['company']:
            comp = auth_data['company']['name']
        else:
            comp = None
        if authorize(auth_data, '/controllers/controller/models/model/applications/application/units', 'post'):
            LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/units [POST] => Authorized!', controller, model, application)
            if juju.app_exists(connection, application):
                juju.add_unit(request.authorization.username, request.authorization.password, controller, auth_data['model']['_key'], application, data.get('amount', 1), data.get('target', 'None'), comp)
                code, response = 202, "Unit is being created"
                LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/units [POST] => Unit is being created, check add_unit.log for more information!', controller, model, application)
            else:
                code, response = errors.does_not_exist('application')
                LOGGER.error('/TENGU/controllers/%s/models/%s/applications/%s/units [POST] => Application does not exist!', controller, model, application)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/TENGU/controllers/%s/models/%s/applications/%s/units [POST] => No Permission to perform this action!', controller, model, application)
        return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        ers = error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)
    finally:
        if 'connection' in locals():
            execute_task(juju.disconnect, connection)


@TENGU.route('/controllers/<controller>/models/<model>/applications/<application>/units/<unitnumber>', methods=['GET'])
def get_unit_info(controller, model, application, unitnumber):
    try:
        controller = unquote(controller)
        model = unquote(model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/units/%s [GET] => receiving call', controller, model, application, unitnumber)
        auth_data = juju.get_connection_info(request.authorization, c_name=controller, m_name=model)
        connection = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data, controller=controller, model=model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/units/%s [GET] => Authenticated!', controller, model, application, unitnumber)
        if authorize(auth_data, '/controllers/controller/models/model/applications/application/units/unitnumber', 'get'):
            LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/units/%s [GET] => Authorized!', controller, model, application, unitnumber)
            if juju.app_exists(connection, application):
                unit = juju.get_unit_info(connection, application, unitnumber)
                if len(unit) != 0:
                    code, response = 200, unit
                    LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/units/%s [GET] => Succesfully retrieved Unit information!', controller, model, application, unitnumber)
                else:
                    code, response = errors.does_not_exist('unit')
                    LOGGER.error('/TENGU/controllers/%s/models/%s/applications/%s/units/%s [GET] => Unit does not exist!', controller, model, application, unitnumber)
            else:
                code, response = errors.does_not_exist('application')
                LOGGER.error('/TENGU/controllers/%s/models/%s/applications/%s/units/%s [GET] => Application does not exist!', controller, model, application, unitnumber)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/TENGU/controllers/%s/models/%s/applications/%s/units/%s [GET] => No Permission to perform this action!', controller, model, application, unitnumber)
        return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        ers = error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)
    finally:
        if 'connection' in locals():
            execute_task(juju.disconnect, connection)


@TENGU.route('/controllers/<controller>/models/<model>/applications/<application>/units/<unitnumber>', methods=['DELETE'])
def remove_unit(controller, model, application, unitnumber):
    try:
        controller = unquote(controller)
        model = unquote(model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/units/%s [DELETE] => receiving call', controller, model, application, unitnumber)
        auth_data = juju.get_connection_info(request.authorization, c_name=controller, m_name=model)
        connection = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data, controller=controller, model=model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/units/%s [DELETE] => Authenticated!', controller, model, application, unitnumber)
        if auth_data['company']:
            comp = auth_data['company']['name']
        else:
            comp = None
        if authorize(auth_data, '/controllers/controller/models/model/applications/application/units/unitnumber', 'del'):
            LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/units/%s [DELETE] => Authorized!', controller, model, application, unitnumber)
            if juju.app_exists(connection, application):
                unit = juju.get_unit_info(connection, application, unitnumber)
                if len(unit) != 0:
                    unit_name = application + '/' + str(unitnumber)
                    juju.remove_unit(request.authorization.username, request.authorization.password, controller, auth_data['model']['_key'], unit_name, comp)
                    code, response = 202, "Unit is being removed"
                    LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/units/%s [DELETE] => Unit is being removed!', controller, model, application, unitnumber)
                else:
                    code, response = errors.does_not_exist('unit')
                    LOGGER.error('/TENGU/controllers/%s/models/%s/applications/%s/units/%s [DELETE] => Unit does not exist!', controller, model, application, unitnumber)
            else:
                code, response = errors.does_not_exist('application')
                LOGGER.error('/TENGU/controllers/%s/models/%s/applications/%s/units/%s [DELETE] => Application does not exist!', controller, model, application, unitnumber)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/TENGU/controllers/%s/models/%s/applications/%s/units/%s [DELETE] => No Permission to perform this action!', controller, model, application, unitnumber)
        return juju.create_response(code, response)
    except KeyError:
        code, response = errors.invalid_data()
        error_log()
        return juju.create_response(code, response)
    except HTTPException:
        ers = error_log()
        raise
    except Exception:
        ers = error_log()
        code, response = errors.cmd_error(ers)
        return juju.create_response(code, response)
    finally:
        if 'connection' in locals():
            execute_task(juju.disconnect, connection)


@TENGU.route('/controllers/<controller>/models/<model>/relations', methods=['GET'])
def get_relations_info(controller, model):
    try:
        controller = unquote(controller)
        model = unquote(model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/relations [GET] => receiving call', controller, model)
        auth_data = juju.get_connection_info(request.authorization, controller, model)
        model_connection = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data, controller, model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/relations [GET] => Authenticated!', controller, model)
        if authorize(auth_data, '/controllers/controller/models/model/relations', 'get'):
            LOGGER.info('/TENGU/controllers/%s/models/%s/relations [GET] => Authorized!', controller, model)
            code, response = 200, juju.get_relations_info(model_connection)
            LOGGER.info('/TENGU/controllers/%s/models/%s/relations [GET] => Succesfully retrieved relation info!', controller, model)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/TENGU/controllers/%s/models/%s/relations [GET] => No permission to perform this acion!', controller, model)
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


@TENGU.route('/controllers/<controller>/models/<model>/relations', methods=['PUT'])
def add_relation(controller, model):
    try:
        controller_name = unquote(controller)
        model_name = unquote(model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/relations [PUT] => receiving call', controller_name, model_name)
        json_data = request.json
        auth_data = juju.get_connection_info(request.authorization, controller_name, model_name)
        model_connection = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data, controller_name, model_name)
        LOGGER.info('/TENGU/controllers/%s/models/%s/relations [PUT] => Authenticated!', controller_name, model_name)
        if authorize(auth_data, '/controllers/controller/models/model/relations', 'put'):
            LOGGER.info('/TENGU/controllers/%s/models/%s/relations [PUT] => Authorized!', controller_name, model_name)
            try:
                relation1 = json_data["app1"]
                relation2 = json_data["app2"]
                # TODO: Model object should be retrieved from connection info.
                model_object = model_manager.ModelObject(name = auth_data["model"]["name"],
                                                         state= auth_data["model"]["state"],
                                                         uuid = auth_data["model"]["uuid"],
                                                         credential_name = auth_data["model"]["credential"])
                # TODO: Controller object should be retrieved from connection info.
                controller_object = controller_manager.ControllerObject(key = auth_data["controller"]["_key"],
                                                                        name = auth_data["controller"]["name"],
                                                                        state= auth_data["controller"]["state"],
                                                                        type = auth_data["controller"]["type"],
                                                                        region = auth_data["controller"]["region"],
                                                                        models = auth_data["controller"]["models"],
                                                                        endpoints = auth_data["controller"]["endpoints"],
                                                                        uuid = auth_data["controller"]["uuid"],
                                                                        ca_cert = auth_data["controller"]["ca_cert"],
                                                                        default_credential_name = auth_data["controller"]["default-credential"])
                juju_username = auth_data["user"]["juju_username"]
                password = request.authorization.password
                w_tengu.add_relation(controller_object, model_object, juju_username, password,
                                     relation1, relation2, model_connection)
                code, response = 202, "Relationship between {} and {} is being created!".format(relation1, relation2)
                LOGGER.info('/TENGU/controllers/%s/models/%s/relations [PUT] => Relationship succesfully created.', controller_name, model_name)
            except ValueError as e:
                code, response = errors.does_not_exist("application" + e.args[0])
                LOGGER.error('/TENGU/controllers/%s/models/%s/relations [PUT] => Application %s does not exist!', controller_name, model_name, e.args[0])
        else:
            code, response = errors.no_permission()
            LOGGER.error('/TENGU/controllers/%s/models/%s/relations [PUT] => No permission to perform this acion!', controller_name, model_name)
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


@TENGU.route('/controllers/<controller>/models/<model>/relations/<application>', methods=['GET'])
def get_relations(controller, model, application):
    try:
        controller = unquote(controller)
        model = unquote(model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/relations/%s [GET] => receiving call', controller, model, application)
        auth_data = juju.get_connection_info(request.authorization, controller, model)
        model_connection = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data, controller, model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/relations/%s [GET] => Authenticated!', controller, model, application)
        if authorize(auth_data, '/controllers/controller/models/model/relations/application', 'get'):
            LOGGER.info('/TENGU/controllers/%s/models/%s/relations/%s [GET] => Authorized!', controller, model, application)
            if juju.app_exists(model_connection, application):
                code, response = 200, juju.get_application_info(model_connection, application)['relations']
                LOGGER.info('/TENGU/controllers/%s/models/%s/relations/%s [GET] => Succesfully retrieved application info!', controller, model, application)
            else:
                code, response = errors.does_not_exist('application')
                LOGGER.error('/TENGU/controllers/%s/models/%s/relations/%s [GET] => Application does not exist!', controller, model, application)
        else:
            code, response = errors.no_permission()
            LOGGER.info('/TENGU/controllers/%s/models/%s/relations/%s [GET] =>  No permission to perform this acion!', controller, model, application)
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


@TENGU.route('/controllers/<controller>/models/<model>/relations/<app1>/<app2>', methods=['DELETE'])
def remove_relation(controller, model, app1, app2):
    try:
        controller = unquote(controller)
        model = unquote(model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/relations/%s/%s [DELETE] => receiving call', controller, model, app1, app2)
        auth_data = juju.get_connection_info(request.authorization, controller, model)
        model_connection = execute_task(juju.authenticate, request.headers['api-key'], request.authorization, auth_data, controller, model)
        LOGGER.info('/TENGU/controllers/%s/models/%s/relations/%s/%s [DELETE] => Authenticated!', controller, model, app1, app2)
        if auth_data['company']:
            comp = auth_data['company']['name']
        else:
            comp = None
        if authorize(auth_data, '/controllers/controller/models/model/relations/app1/app2', 'del'):
            LOGGER.info('/TENGU/controllers/%s/models/%s/relations/%s/%s [DELETE] => Authorized!', controller, model, app1, app2)
            # TODO: Does it have to be possible to give relations with ':' f.e. 'wordpress:db'
            app1_name = app1
            app2_name = app2
            if ':' in app1:
                app1_name = app1.split(':')[0]
            if ':' in app2:
                app2_name = app2.split(':')[0]

            if juju.app_exists(model_connection, app1_name) and juju.app_exists(model_connection, app2_name):
                endpoint = auth_data["controller"]["endpoints"][0]
                cacert = auth_data["controller"]["ca_cert"]
                m_name = auth_data["model"]["name"]
                uuid = auth_data["model"]["uuid"]
                juju_username = auth_data["user"]["juju_username"]
                password = request.authorization.password

                juju.remove_relation(controller, endpoint, cacert, m_name, uuid,
                                  juju_username, password, app1, app2, comp)
                code, response = 202, 'The relation is being removed!'
                LOGGER.info('/TENGU/controllers/%s/models/%s/relations/%s/%s [DELETE] => Relation is being removed!', controller, model, app1, app2)
            else:
                code, response = errors.does_not_exist('application')
                LOGGER.error('/TENGU/controllers/%s/models/%s/relations/%s/%s [DELETE] => Application does not exist!', controller, model, app1, app2)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/TENGU/controllers/%s/models/%s/relations/%s/%s [DELETE] => No Permission to perform this action!', controller, model, app1, app2)
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


# On hold
# TO DO: Backup and restore calls
@TENGU.route('/backup', methods=['GET'])
def backup_controllers():
    try:
        LOGGER.info('/TENGU/backup [GET] => receiving call')
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        if token.is_admin:
            apidir = juju.get_api_dir()
            homedir = '/home/{}/.local/share/juju'.format(juju.get_api_user())
            try:
                shutil.copytree('/home/{}/credentials'.format(juju.get_api_user()), '{}/backup/credentials'.format(apidir))
                shutil.copytree(homedir, '{}/backup/juju'.format(apidir))
            except Exception: # FileExistsError
                os.rmdir('{}/backup/credentials'.format(apidir))
                os.rmdir(homedir)
                shutil.copytree('/home/{}/credentials'.format(juju.get_api_user()), '{}/backup/credentials'.format(apidir))
                shutil.copytree(homedir, '{}/backup/juju'.format(apidir))
            except Exception:  # FileNotFoundError
                pass
            shutil.make_archive('{}/backup'.format(apidir), 'zip', '{}/backup/'.format(apidir))
            return send_file('{}/backup.zip'.format(apidir))
        else:
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


# On hold
@TENGU.route('/restore', methods=['POST'])
def restore_controllers():
    try:
        LOGGER.info('/TENGU/restore [POST] => receiving call')
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        if token.is_admin:
            homedir = '/home/{}/.local/share/juju'.format(juju.get_api_user())
            if 'backup' in request.files:
                file = request.files['backup']
                filename = file.filename
                tmpdir = tempfile.mkdtemp()
                saved_loc = os.path.join(tmpdir, filename)
                file.save(saved_loc)
                zip_ref = zipfile.ZipFile(saved_loc, 'r')
                zip_ref.extractall(tmpdir)
                zip_ref.close()
                shutil.rmtree(homedir)
                shutil.rmtree('/home/{}/credentials'.format(juju.get_api_user()))
                shutil.copytree('{}/juju'.format(tmpdir), homedir)
                shutil.copytree('{}/credentials'.format(tmpdir), '/home/{}/credentials'.format(juju.get_api_user()))
                code, response = 200, 'succesfully restored backup'
            else:
                code, response = 400, 'No backup file found'
        else:
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

def error_log():
    exc_type, exc_value, exc_traceback = sys.exc_info()
    lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
    for l in lines:
        LOGGER.error(l)
    return lines
