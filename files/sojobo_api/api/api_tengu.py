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
from werkzeug.exceptions import HTTPException
from flask import send_file, request, Blueprint
from sojobo_api.api import w_errors as errors, w_juju as juju
from sojobo_api.api.w_juju import execute_task


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
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/TENGU/controllers [GET] => Authenticated!')
        if token.is_admin:
            code, response = 200, execute_task(juju.get_all_controllers)
            LOGGER.info('/TENGU/controllers [GET] => Succesfully retrieved all controllers!')
        else:
            code, response = errors.no_permission()
            LOGGER.error('/TENGU/controllers [GET] => No Permission to perform action!')
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


@TENGU.route('/controllers', methods=['POST'])
def create_controller():
    try:
        if request.json is None:
            data = request.form
        else:
            data = request.json
        url = request.url_rule
        LOGGER.info('%s [POST] => receiving call', url)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('%s [POST] => Authenticated', url)
        if token.is_admin:
            controller = juju.check_input(data['controller'])
            LOGGER.info('%s [POST] => Creating Controller %s', url, controller)
            c_type = execute_task(juju.check_c_type, data['type'])
            if execute_task(juju.controller_exists, controller):
                code, response = errors.already_exists('controller')
                LOGGER.error('%s [POST] => Controller %s already exists', url,  controller)
            else:
                code, response = execute_task(juju.create_controller, c_type,
                                              controller, data['region'], data['credential'])
                LOGGER.info('%s [POST] => Creating Controller %s, check add_controller.log for more details! ', url, controller)
        else:
            code, response = errors.no_permission()
            LOGGER.error('%s [POST] => No Permission to perform action!', url)
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


@TENGU.route('/controllers/<controller>', methods=['GET'])
def get_controller_info(controller):
    try:
        LOGGER.info('/TENGU/controllers/%s [GET] => receiving call', controller)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/TENGU/controllers/%s [GET] => Authenticated!', controller)
        con = execute_task(juju.authorize, token, juju.check_input(controller))
        LOGGER.info('/TENGU/controllers/%s [GET] => Authorized!', controller)
        code, response = 200, execute_task(juju.get_controller_info, token, con)
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


@TENGU.route('/controllers/<controller>', methods=['DELETE'])
def delete_controller(controller):
    try:
        LOGGER.info('/TENGU/controllers/%s [DELETE] => receiving call', controller)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/TENGU/controllers/%s [DELETE] => Authenticated!', controller)
        con = execute_task(juju.authorize, token, juju.check_input(controller))
        LOGGER.info('/TENGU/controllers/%s [DELETE] => Authorized!', controller)
        if con.c_access == 'superuser':
            LOGGER.info('/TENGU/controllers/%s [DELETE] => Deleting Controller!', controller)
            execute_task(juju.delete_controller, con)
            code, response = 200, execute_task(juju.get_all_controllers)
            LOGGER.info('/TENGU/controllers/%s [DELETE] => Succesfully deleted controller!', controller)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/TENGU/controllers/%s [DELETE] => No Permission to perform this action!', controller)
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


@TENGU.route('/controllers/<controller>/models', methods=['POST'])
def create_model(controller):
    try:
        LOGGER.info('/TENGU/controllers/%s/models [POST] => receiving call', controller)
        data = request.json
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/TENGU/controllers/%s/models [POST] => Authenticated!', controller)
        con = execute_task(juju.authorize, token, juju.check_input(controller))
        LOGGER.info('/TENGU/controllers/%s/models [POST] => Authorized!', controller)
        model = juju.check_input(data['model'])
        credentials = juju.check_input(data['credential'])
        if con.c_access == 'add-model' or con.c_access == 'superuser':
            LOGGER.info('/TENGU/controllers/%s/models [POST] => Creating model, check add_model.log for more details', controller)
            code, response = execute_task(juju.create_model, token, con.c_name, model, credentials)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/TENGU/controllers/%s/models [POST] => No Permission to perform this action!', controller)
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


@TENGU.route('/controllers/<controller>/models', methods=['GET'])
def get_models_info(controller):
    try:
        LOGGER.info('/TENGU/controllers/%s/models [GET] => receiving call', controller)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/TENGU/controllers/%s/models [GET] => Authenticated!', controller)
        con = execute_task(juju.authorize, token, juju.check_input(controller))
        LOGGER.info('/TENGU/controllers/%s/models [GET] => Authorized!', controller)
        code, response = 200, execute_task(juju.get_models_info, token, con)
        LOGGER.info('/TENGU/controllers/%s/models [GET] => modelinfo retieved for all models!', controller)
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


@TENGU.route('/controllers/<controller>/models/<model>', methods=['GET'])
def get_model_info(controller, model):
    try:
        LOGGER.info('/TENGU/controllers/%s/models/%s [GET] => receiving call', controller, model)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/TENGU/controllers/%s/models/%s [GET] => Authenticated!', controller, model)
        con, mod = execute_task(juju.authorize, token, juju.check_input(controller), juju.check_input(model))
        LOGGER.info('/TENGU/controllers/%s/models/%s [GET] => Authorized!', controller, model)
        code, response = 200, execute_task(juju.get_model_info, token, con, mod)
        LOGGER.info('/TENGU/controllers/%s/models/%s [GET] => model information retrieved!', controller, model)
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


@TENGU.route('/controllers/<controller>/models/<model>', methods=['POST'])
def add_bundle(controller, model):
    try:
        LOGGER.info('/TENGU/controllers/%s/models/%s [POST] => receiving call', controller, model)
        data = request.json
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/TENGU/controllers/%s/models/%s [POST] => Authenticated!', controller, model)
        con, mod = execute_task(juju.authorize, token, juju.check_input(controller), juju.check_input(model))
        LOGGER.info('/TENGU/controllers/%s/models/%s [POST] => Authorized!', controller, model)
        if mod.m_access == 'admin' or mod.m_access == 'write':
            LOGGER.info('/TENGU/controllers/%s/models/%s [POST] => Bundle is being deployed, check bundle_deployment.log for more information!', controller, model)
            execute_task(juju.add_bundle, token, con.c_name, mod.m_name, data['bundle'])
            code, response = 202, "Bundle is being deployed"
        else:
            code, response = errors.no_permission()
            LOGGER.error('/TENGU/controllers/%s/models/%s [POST] => No Permission to perform action!', controller, model)
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


@TENGU.route('/controllers/<controller>/models/<model>', methods=['DELETE'])
def delete_model(controller, model):
    try:
        LOGGER.info('/TENGU/controllers/%s/models/%s [DELETE] => receiving call', controller, model)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/TENGU/controllers/%s/models/%s [DELETE] => Authenticated!', controller, model)
        con, mod = execute_task(juju.authorize, token, juju.check_input(controller), juju.check_input(model))
        LOGGER.info('/TENGU/controllers/%s/models/%s [DELETE] => Authorized!', controller, model)
        if mod.m_access == 'admin':
            code, response = 200, execute_task(juju.delete_model, token, con, mod)
            LOGGER.info('/TENGU/controllers/%s/models/%s [DELETE] => Model succesfully deleted!', controller, model)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/TENGU/controllers/%s/models/%s [DELETE] => No Permission to perform this action!', controller, model)
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


@TENGU.route('/controllers/<controller>/models/<model>/applications', methods=['GET'])
def get_applications_info(controller, model):
    try:
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications [GET] => receiving call', controller, model)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications [GET] => Authenticated!', controller, model)
        con, mod = execute_task(juju.authorize, token, juju.check_input(controller), juju.check_input(model))
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications [GET] => Authorized!', controller, model)
        code, response = 200, execute_task(juju.get_applications_info, token, mod)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications [GET] => succesfully retieved applications info!', controller, model)
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


@TENGU.route('/controllers/<controller>/models/<model>/applications', methods=['POST'])
def add_application(controller, model):
    try:
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications [POST] => receiving call', controller, model)
        data = request.json
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications [POST] => Authenticated!', controller, model)
        con, mod = execute_task(juju.authorize, token, juju.check_input(controller), juju.check_input(model))
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications [POST] => Authorized!', controller, model)
        if execute_task(juju.app_exists, token, con, mod, data['application']):
            code, response = errors.already_exists('application')
            LOGGER.error('/TENGU/controllers/%s/models/%s/applications [POST] => Application already exists!', controller, model)
        else:
            if mod.m_access == 'write' or mod.m_access == 'admin':
                series = juju.check_input(data.get('series', None), True)
                config = juju.check_input(data.get('config', None), True)
                machine = juju.check_input(data.get('target', None), True)
                app_name = juju.check_input(data.get('app_name', None), True)
                units = juju.check_input(data.get('units', "1"))
                app = juju.check_input(data['application'])
                execute_task(juju.deploy_app, token, mod, app, name=app_name, ser=series, tar=machine, con=config, num_of_units=int(units))
                code, response = 200, execute_task(juju.get_application_info, token, mod, app)
                LOGGER.info('/TENGU/controllers/%s/models/%s/applications [POST] => succesfully deployed application!', controller, model)
            else:
                code, response = errors.no_permission()
                LOGGER.error('/TENGU/controllers/%s/models/%s [DELETE] => No Permission to perform this action!', controller, model)
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


@TENGU.route('/controllers/<controller>/models/<model>/applications/<application>', methods=['GET'])
def get_application_info(controller, model, application):
    try:
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s [GET] => receiving call', controller, model, application)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s [GET] => Authenticated!', controller, model, application)
        con, mod = execute_task(juju.authorize, token, juju.check_input(controller), juju.check_input(model))
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s [GET] => authorized!', controller, model, application)
        app = juju.check_input(application)
        if execute_task(juju.app_exists, token, con, mod, app):
            code, response = 200, execute_task(juju.get_application_info, token, mod, app)
            LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s [GET] => Succesfully retrieved application info!', controller, model, application)
        else:
            code, response = errors.does_not_exist('application')
            LOGGER.error('/TENGU/controllers/%s/models/%s/applications/%s [GET] => Application does not exist!', controller, model, application)
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


@TENGU.route('/controllers/<controller>/models/<model>/applications/<application>', methods=['PUT'])
def expose_application(controller, model, application):
    data = request.json
    try:
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s [PUT] => receiving call', controller, model, application)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s [PUT] => Authenticated!', controller, model, application)
        con, mod = execute_task(juju.authorize, token, juju.check_input(controller), juju.check_input(model))
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s [PUT] => Authorized!', controller, model, application)
        app = juju.check_input(application)
        exposed = True if data['expose'] == "True" else False
        if execute_task(juju.check_if_exposed, token, mod, app) == exposed:
            code, response = 200, execute_task(juju.get_application_info, token, mod, app)
            LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s [PUT] => Application already exposed!', controller, model, application)
        else:
            if exposed:
                execute_task(juju.expose_app, token, mod, app)
                LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s [PUT] => Application exposed!', controller, model, application)
            else:
                execute_task(juju.unexpose_app, token, mod, app)
                LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s [PUT] => Application unexposed!', controller, model, application)
            code, response = 200, execute_task(juju.get_application_info, token, mod, app)
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


@TENGU.route('/controllers/<controller>/models/<model>/applications/<application>', methods=['DELETE'])
def remove_app(controller, model, application):
    try:
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s [DELETE] => receiving call', controller, model, application)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s [DELETE] => Authenticated!', controller, model, application)
        con, mod = execute_task(juju.authorize, token, juju.check_input(controller), juju.check_input(model))
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s [DELETE] => Authorized!', controller, model, application)
        app = juju.check_input(application)
        if mod.m_access == 'write' or mod.m_access == 'admin':
            if execute_task(juju.app_exists, token, con, mod, app):
                execute_task(juju.remove_app, token, mod, app)
                code, response = 202, "The application is being removed"
                LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s [DELETE] => Removing application!', controller, model, application)
            else:
                code, response = errors.does_not_exist('application')
                LOGGER.error('/TENGU/controllers/%s/models/%s/applications/%s [DELETE] => Application does not exist!', controller, model, application)
        else:
            code, response = errors.no_permission()
            LOGGER.error('/TENGU/controllers/%s/models/%s/applications/%s [DELETE] => No Permission to perform this action!', controller, model, application)
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


@TENGU.route('/controllers/<controller>/models/<model>/applications/<application>/config', methods=['GET'])
def get_application_config(controller, model, application):
    try:
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/config [GET] => receiving call', controller, model, application)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/config [GET] => Authenticated!', controller, model, application)
        con, mod = execute_task(juju.authorize, token, juju.check_input(controller), juju.check_input(model))
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/config [GET] => Authorized!', controller, model, application)
        app = juju.check_input(application)
        code, response = 200, execute_task(juju.get_application_config, token, mod, app)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/config [GET] => Succesfully retrieved application config!', controller, model, application)
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


@TENGU.route('/controllers/<controller>/models/<model>/applications/<application>/config', methods=['PUT'])
def set_application_config(controller, model, application):
    try:
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/config [PUT] => receiving call', controller, model, application)
        data = request.json
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/config [PUT] => Authenticated!', controller, model, application)
        con, mod = execute_task(juju.authorize, token, juju.check_input(controller), juju.check_input(model))
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/config [PUT] => Authorized!', controller, model, application)
        if mod.m_access == 'write' or mod.m_access == 'admin':
            app = juju.check_input(application)
            execute_task(juju.set_application_config, token, mod, app, data.get('config', None))
            LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/config [PUT] => Config parameter is being changed!', controller, model, application)
            code, response = 202, "The config parameter is being changed"
        else:
            code, response = errors.no_permission()
            LOGGER.error('/TENGU/controllers/%s/models/%s/applications/%s/config [PUT] => No Permission to perform this action!', controller, model, application)
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


@TENGU.route('/controllers/<controller>/models/<model>/machines', methods=['GET'])
def get_machines_info(controller, model):
    try:
        LOGGER.info('/TENGU/controllers/%s/models/%s/machines [GET] => receiving call', controller, model)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        con, mod = execute_task(juju.authorize, token, juju.check_input(controller), juju.check_input(model))
        code, response = 200, execute_task(juju.get_machines_info, token, mod)
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


@TENGU.route('/controllers/<controller>/models/<model>/machines/<machine>', methods=['GET'])
def get_machine_info(controller, model, machine):
    try:
        LOGGER.info('/TENGU/controllers/%s/models/%s/machines/%s [GET] => receiving call', controller, model, machine)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        con, mod = execute_task(juju.authorize, token, juju.check_input(controller), juju.check_input(model))
        mach = juju.check_input(machine)
        if execute_task(juju.machine_exists, token, mod, mach):
            code, response = 200, execute_task(juju.get_machine_info, token, mod, mach)
        else:
            code, response = errors.does_not_exist('machine')
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


@TENGU.route('/controllers/<controller>/models/<model>/machines', methods=['POST'])
def add_machine(controller, model):
    try:
        LOGGER.info('/TENGU/controllers/%s/models/%s/machines [POST] => receiving call', controller, model)
        data = request.json
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        con, mod = execute_task(juju.authorize, token, juju.check_input(controller), juju.check_input(model))
        if mod.m_access == 'write' or mod.m_access == 'admin':
            series = juju.check_input(data.get('series', None), True)
            constraints = juju.check_input(data.get('constraints', None), True)
            if execute_task(juju.cloud_supports_series, con, series):
                execute_task(juju.add_machine, token, mod, series, constraints)
                code, response = 202, 'machine is being deployed'
            else:
                code, response = 400, 'This cloud does not support this version of Ubuntu'
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


@TENGU.route('/controllers/<controller>/models/<model>/machines/<machine>', methods=['DELETE'])
def remove_machine(controller, model, machine):
    try:
        LOGGER.info('/TENGU/controllers/%s/models/%s/machines/%s [DELETE] => receiving call', controller, model, machine)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        con, mod = execute_task(juju.authorize, token, juju.check_input(controller), juju.check_input(model))
        mach = juju.check_input(machine)
        if execute_task(juju.machine_exists, token, mod, mach):
            if mod.m_access == 'write' or mod.m_access == 'admin':
                execute_task(juju.remove_machine, token, con, mod, mach)
                code, response = 202, 'Machine being removed'
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.does_not_exist('machine')
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


@TENGU.route('/controllers/<controller>/models/<model>/applications/<application>/units', methods=['GET'])
def get_units_info(controller, model, application):
    try:
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/units [GET] => receiving call', controller, model, application)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        con, mod = execute_task(juju.authorize, token, juju.check_input(controller), juju.check_input(model))
        app = juju.check_input(application)
        if execute_task(juju.app_exists, token, con, mod, app):
            code, response = 200, execute_task(juju.get_units_info, token, mod, app)
        else:
            code, response = errors.does_not_exist('application')
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


@TENGU.route('/controllers/<controller>/models/<model>/applications/<application>/units', methods=['POST'])
def add_unit(controller, model, application):
    try:
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/units [POST] => receiving call', controller, model, application)
        data = request.json
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        con, mod = execute_task(juju.authorize, token, juju.check_input(controller), juju.check_input(model))
        app = juju.check_input(application)
        if execute_task(juju.app_exists, token, con, mod, app):
            if mod.m_access == 'write' or mod.m_access == 'admin':
                execute_task(juju.add_unit, token, con, mod, application, data.get('amount', 1), data.get('target', 'None'))
                code, response = 202, "Units being created"
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.does_not_exist('application')
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


@TENGU.route('/controllers/<controller>/models/<model>/applications/<application>/units/<unitnumber>', methods=['DELETE'])
def remove_unit(controller, model, application, unitnumber):
    try:
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/units/%s [DELETE] => receiving call', controller, model, application, unitnumber)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        con, mod = execute_task(juju.authorize, token, juju.check_input(controller), juju.check_input(model))
        app = juju.check_input(application)
        unum = juju.check_input(unitnumber)
        if execute_task(juju.get_unit_info, token, mod, app, unum) is not {}:
            if mod.m_access == 'write' or mod.m_access == 'admin':
                execute_task(juju.remove_unit, token, mod, app, unum)
                code, response = 202, "Unit is being removed"
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.does_not_exist('unit')
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


@TENGU.route('/controllers/<controller>/models/<model>/applications/<application>/units/<unitnumber>', methods=['GET'])
def get_unit_info(controller, model, application, unitnumber):
    try:
        LOGGER.info('/TENGU/controllers/%s/models/%s/applications/%s/units/%s [GET] => receiving call', controller, model, application, unitnumber)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        con, mod = execute_task(juju.authorize, token, juju.check_input(controller), juju.check_input(model))
        app = juju.check_input(application)
        unum = juju.check_input(unitnumber)
        unit = execute_task(juju.get_unit_info, token, mod, app, unum)
        if unit is not {}:
            code, response = 200, unit
        else:
            code, response = errors.does_not_exist('unit')
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


@TENGU.route('/controllers/<controller>/models/<model>/relations', methods=['GET'])
def get_relations_info(controller, model):
    try:
        LOGGER.info('/TENGU/controllers/%s/models/%s/relations [GET] => receiving call', controller, model)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        con, mod = execute_task(juju.authorize, token, juju.check_input(controller), juju.check_input(model))
        code, response = 200, execute_task(juju.get_relations_info, token, mod)
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
        LOGGER.info('/TENGU/controllers/%s/models/%s/relations [PUT] => receiving call', controller, model)
        data = request.json
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        con, mod = execute_task(juju.authorize, token, juju.check_input(controller), juju.check_input(model))
        app1, app2 = juju.check_input(data['app1']), juju.check_input(data['app2'])
        if execute_task(juju.app_exists, token, con, mod, app1) and execute_task(juju.app_exists, token, con, mod, app2):
            if mod.m_access == 'write' or mod.m_access == 'admin':
                execute_task(juju.add_relation, token, mod, app1, app2)
                code, response = 200, execute_task(juju.get_relations_info, token, mod)
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.does_not_exist('application')
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
        LOGGER.info('/TENGU/controllers/%s/models/%s/relations/%s [GET] => receiving call', controller, model, application)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        con, mod = execute_task(juju.authorize, token, juju.check_input(controller), juju.check_input(model))
        app = juju.check_input(application)
        if execute_task(juju.app_exists, token, con, mod, app):
            code, response = 200, execute_task(juju.get_application_info, token, mod, app)['relations']
        else:
            code, response = errors.does_not_exist('application')
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
        LOGGER.info('/TENGU/controllers/%s/models/%s/relations/%s/%s [DELETE] => receiving call', controller, model, app1, app2)
        token = execute_task(juju.authenticate, request.headers['api-key'], request.authorization)
        con, mod = execute_task(juju.authorize, token, juju.check_input(controller), juju.check_input(model))
        appl1, appl2 = juju.check_input(app1), juju.check_input(app2)
        if execute_task(juju.app_exists, token, con, mod, appl1) and execute_task(juju.app_exists, token, con, mod, appl2):
            if mod.m_access == 'write' or mod.m_access == 'admin':
                execute_task(juju.remove_relation, token, mod, appl1, appl2)
                code, response = 202, 'The relation is being removed'
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.no_app()
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
