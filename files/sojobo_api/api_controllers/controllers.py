# pylint: disable=c0111,c0301,c0325,w0406
###############################################################################
# CONTROLLER FUNCTIONS
###############################################################################
import shutil

from flask import send_file, request, Blueprint
from .. import errors, helpers, juju


CONTROLLERS = Blueprint('controllers', __name__)


@CONTROLLERS.route('/create', methods=['POST'])
def create():
    data = request.form
    try:
        token = juju.authenticate(data['api_key'], request.authorization)
        if token.is_admin:
            response = juju.create_controller(token, data['type'], data['name'], data['region'], data['credentials'])
            code = 200
        else:
            code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return helpers.create_response(code, {'message': response})


@CONTROLLERS.route('/delete', methods=['DELETE'])
def delete():
    data = request.form
    try:
        token = juju.authenticate(data['api_key'], request.authorization, data['controller'])
        if token.c_access == 'superuser':
            code, response = 200, juju.delete_controller(token)
        else:
            code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return helpers.create_response(code, {'message': response})


@CONTROLLERS.route('/backup', methods=['GET'])
def backup_controllers():
    data = request.args
    try:
        token = juju.authenticate(data['api_key'], request.authorization)
        if token.is_admin:
            apidir = helpers.get_api_dir
            homedir = '/home/ubuntu/.local/share/juju'
            shutil.copy2('{}/install_credentials.py'.format(apidir), '{}/backup/install_credentials.py'.format(apidir))
            shutil.copy2('{}/clouds.yaml'.format(homedir), '{}/backup/clouds.yaml'.format(apidir))
            shutil.copy2('{}/credentials.yaml'.format(homedir), '{}/backup/credentials.yaml'.format(apidir))
            shutil.copy2('{}/controllers.yaml'.format(homedir), '{}/backup/controllers.yaml'.format(apidir))
            shutil.make_archive('{}/backup'.format(apidir), 'zip', '{}/backup/'.format(apidir))
            return send_file('{}/backup.zip'.format(apidir))
        else:
            code, response = errors.no_permission()
    except KeyError:
        code, response = errors.invalid_data()
    return helpers.create_response(code, {'message': response})
