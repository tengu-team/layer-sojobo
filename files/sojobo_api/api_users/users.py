# pylint: disable=c0111,c0301,c0325
###############################################################################
# USER FUNCTIONS
###############################################################################
from os import mkdir
from os.path import dirname, realpath
import shutil
import tempfile

from flask import send_file

from .. import helpers, juju
from flask import request, Blueprint


users = Blueprint('users', __name__)


@users.route('/create', methods=['POST'])
def create():
    data = request.form
    helpers.check_api_key(data['api-key'])
    token = juju.authenticate(request.authorization)
    if juju.user_exists(data['username']):
        response = {'message': 'The user already exists'}
    else:
        juju.create_user(data['username'], data['password'])
        response = {'gui-url': juju.get_gui_url(token)}
    return helpers.create_response(200, response)


@users.route('/delete', methods=['DELETE'])
def delete():
    return None


@users.route('/changepassword', methods=['PUT'])
def change_password():
    return None


@users.route('/addtocontroller', methods=['POST'])
def add_to_controller():
    return None


@users.route('/removefromcontroller', methods=['POST'])
def remove_from_controller():
    return None


@users.route('/addtomodel', methods=['POST'])
def add_to_model():
    return None


@users.route('/removefrommodel', methods=['POST'])
def remove_from_model():
    return None


@users.route('/credentials.zip', methods=['GET'])
def get_credentials():
    credentials = juju.get_credentials(juju.authenticate(request.authorization))
    clouds = juju.get_clouds()
    controllers = helpers.get_controllers(juju.CONTROLLER_NAME)
    tmpdir = tempfile.mkdtemp()
    mkdir('{}/creds'.format(tmpdir))
    helpers.write_yaml('{}/creds/clouds.yaml'.format(tmpdir), clouds)
    helpers.write_yaml('{}/creds/credentials.yaml'.format(tmpdir), credentials)
    helpers.write_yaml('{}/creds/controllers.yaml'.format(tmpdir), controllers)
    shutil.copy2("{}/install_credentials.py".format(dirname(realpath(__file__))), '{}/creds/install_credentials.py'.format(tmpdir))
    shutil.make_archive('{}/creds'.format(tmpdir), 'zip', '{}/creds/'.format(tmpdir))
    return send_file('{}/creds.zip'.format(tmpdir))
