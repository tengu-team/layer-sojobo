# pylint: disable=c0111,c0301,c0325
###############################################################################
# CONTROLLER FUNCTIONS
###############################################################################
from .. import helpers, juju
from flask import request, Blueprint


controllers = Blueprint('controllers', __name__)


@controllers.route('/create', methods=['POST'])
def create():
    data = request.form
    try:
        helpers.check_api_key(data['api_key'])
        response = juju.create_controller(data['type'], data['name'], data['region'], data['credentials'])
        status = 200
    except KeyError:
        status, response = helpers.invalid_data()
    return helpers.create_response(status, {'message': response})


@controllers.route('/delete', methods=['DELETE'])
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
