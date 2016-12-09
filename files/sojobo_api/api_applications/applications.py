# pylint: disable=c0111,c0301,c0325,w0406
###############################################################################
# APPLICATION FUNCTIONS
###############################################################################
from flask import request, Blueprint
from .. import errors, helpers, juju


APPLICATIONS = Blueprint('applications', __name__)


@APPLICATIONS.route('/addapp', methods=['PUT'])
def add_app():
    data = request.form
    try:
        token = juju.authenticate(data['api_key'], request.authorization, data['controller'], data['model'])
        app_name = data['app_name']
        if juju.app_exists(token, app_name):
            code, response = 200, 'The application already exists.'
        else:
            if token.m_access == 'write' or token.m_access == 'admin':
                series = data.get('series', None)
                machine = data.get('target', None)
                if series is not None and machine is not None:
                    if series == juju.get_machine_series(token, machine):
                        code, response = 200, juju.deploy_app(token, app_name, series, machine)
                    else:
                        code, response = 400, 'Target and application have a different version of Ubuntu'
                elif series is not None:
                    if juju.app_supports_series(app_name, series):
                        code, response = 200, juju.deploy_app(token, app_name, series)
                    else:
                        code, response = 400, 'The application does not support this version of Ubuntu'
                else:
                    code, response = 200, juju.deploy_app(token, app_name)
            else:
                code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return helpers.create_response(code, {'message': response})


@APPLICATIONS.route('/removeapp', methods=['DELETE'])
def remove_app():
    data = request.form
    try:
        token = juju.authenticate(data['api_key'], request.authorization, data['controller'], data['model'])
        appname = data['app_name']
        if juju.app_exists(token, appname):
            if token.m_access == 'write' or token.m_access == 'admin':
                code, response = 200, juju.remove_app(token, data['app_name'])
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.no_app()
    except KeyError:
        code, response = errors.invalid_data()
    return helpers.create_response(code, {'message': response})


@APPLICATIONS.route('/addmachine', methods=['PUT'])
def add_machine():
    data = request.form
    try:
        token = juju.authenticate(data['api_key'], request.authorization, data['controller'], data['model'])
        if token.m_access == 'write' or token.m_access == 'admin':
            series = data.get('series', None)
            if series is not None:
                if juju.cloud_supports_series(token, series):
                    code, response = 200, juju.add_machine(token, series)
                else:
                    code, response = 400, 'This cloud does not support this version of Ubuntu'
            else:
                code, response = 200, juju.add_machine(token)
        else:
            code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return helpers.create_response(code, {'message': response})


@APPLICATIONS.route('/removemachine', methods=['DELETE'])
def remove_machine():
    data = request.form
    try:
        token = juju.authenticate(data['api_key'], request.authorization, data['controller'], data['model'])
        machine = data['machine']
        if juju.machine_exists(token, machine):
            if token.m_access == 'write' or token.m_access == 'admin':
                code, response = 200, juju.remove_machine(token, data['machine'])
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.no_machine()
    except KeyError:
        code, response = errors.invalid_data()
    return helpers.create_response(code, {'message': response})


@APPLICATIONS.route('/addunit', methods=['PUT'])
def add_unit():
    data = request.form
    try:
        token = juju.authenticate(data['api_key'], request.authorization, data['controller'], data['model'])
        app = data['app']
        if juju.app_exists(token, app):
            if token.m_access == 'write' or token.m_access == 'admin':
                code, response = 200, juju.add_unit(token, app, data.get('target', None))
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.no_app()
    except KeyError:
        code, response = errors.invalid_data()
    return helpers.create_response(code, {'message': response})


@APPLICATIONS.route('/removeunit', methods=['DELETE'])
def remove_unit():
    data = request.form
    try:
        token = juju.authenticate(data['api_key'], request.authorization, data['controller'], data['model'])
        unit = data['unit']
        if juju.unit_exists(token, unit):
            if token.m_access == 'write' or token.m_access == 'admin':
                code, response = 200, juju.remove_unit(token, unit)
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.no_app()
    except KeyError:
        code, response = errors.invalid_data()
    return helpers.create_response(code, {'message': response})


@APPLICATIONS.route('/addrelation', methods=['PUT'])
def add_relation():
    data = request.form
    try:
        token = juju.authenticate(data['api_key'], request.authorization, data['controller'], data['model'])
        app1, app2 = data['app1'], data['app2']
        if juju.app_exists(token, app1) and juju.app_exists(token, app2):
            if token.m_access == 'write' or token.m_access == 'admin':
                code, response = 200, juju.add_relation(token, app1, app2)
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.no_app()
    except KeyError:
        code, response = errors.invalid_data()
    return helpers.create_response(code, {'message': response})


@APPLICATIONS.route('/removerelation', methods=['DELETE'])
def remove_relation():
    data = request.form
    try:
        token = juju.authenticate(data['api_key'], request.authorization, data['controller'], data['model'])
        app1, app2 = data['app1'], data['app2']
        if juju.app_exists(token, app1) and juju.app_exists(token, app2):
            if token.m_access == 'write' or token.m_access == 'admin':
                code, response = 200, juju.remove_relation(token, app1, app2)
            else:
                code, response = errors.no_permission()
        else:
            code, response = errors.no_app()
    except KeyError:
        code, response = errors.invalid_data()
    return helpers.create_response(code, {'message': response})


@APPLICATIONS.route('/config/<controllername>/<modelname>/<appname>', methods=['GET'])
def get_config(controllername, modelname, appname):
    try:
        token = juju.authenticate(request.args['api_key'], request.authorization, controllername, modelname)
        code, response = 200, juju.config(token, appname)
    except KeyError:
        code, response = errors.invalid_data()
    return helpers.create_response(code, {'message': response})


@APPLICATIONS.route('/info/<controllername>/<modelname>/<appname>', methods=['GET'])
def get_info(controllername, modelname, appname):
    try:
        token = juju.authenticate(request.args['api_key'], request.authorization, controllername, modelname)
        if juju.app_exists(token, appname):
            code, response = 200, juju.get_app_info(token, appname)
        else:
            code, response = errors.no_app()
    except KeyError:
        code, response = errors.invalid_data()
    return helpers.create_response(code, {'message': response})
