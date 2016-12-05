# pylint: disable=c0111,c0301,c0325
###############################################################################
# CONTROLLER FUNCTIONS
###############################################################################
import helpers
from .. import juju


def create(request):
    data = request.form
    helpers.check_api_key(data['api-key'])
    response = juju.create_controller(data['name'], data['credentials'])
    return helpers.create_response(200, response)


def delete(request):
    data = request.fomr
    helpers.check_api_key(data['api-key'])
    
