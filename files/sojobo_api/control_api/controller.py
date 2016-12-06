# pylint: disable=c0111,c0301,c0325
###############################################################################
# CONTROLLER FUNCTIONS
###############################################################################
from .. import helpers
import juju


def create(request):
    data = request.form
    try:
        helpers.check_api_key(data['api-key'])
        response = juju.create_controller(data['type'], data['name'], data['region'], data['credentials'])
        status = 200
    except KeyError:
        status, response = helpers.invalid_data()
    return helpers.create_response(status, response)


def delete(request):
    data = request.form
    try:
        helpers.check_api_key(data['api-key'])
        token = juju.authenticate(request.authorization, data['controller'])
        response = juju.delete_controller(token)
        status = 200
    except KeyError:
        status, response = helpers.invalid_data()
    return helpers.create_response(status, response)
