# pylint: disable=c0111,c0301,c0325,w0406
###############################################################################
# CONTROLLER FUNCTIONS
###############################################################################
from flask import request, Blueprint
from .. import helpers, juju


CONTROLLERS = Blueprint('controllers', __name__)


@CONTROLLERS.route('/create', methods=['POST'])
def create():
    data = request.form
    try:
        helpers.check_api_key(data['api_key'])
        response = juju.create_controller(data['type'], data['name'], data['region'], data['credentials'])
        status = 200
    except KeyError:
        status, response = helpers.invalid_data()
    return helpers.create_response(status, {'message': response})


@CONTROLLERS.route('/delete', methods=['DELETE'])
def delete():
    data = request.form
    try:
        helpers.check_api_key(data['api_key'])
        token = juju.authenticate(request.authorization, data['controller'])
        if token.c_access == 'superuser':
            response = juju.delete_controller(token)
            status = 200
        else:
            response = 'You do not have permission to delete this controller!'
            status = 403
    except KeyError:
        status, response = helpers.invalid_data()
    return helpers.create_response(status, {'message': response})
