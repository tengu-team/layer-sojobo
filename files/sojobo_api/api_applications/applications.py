# pylint: disable=c0111,c0301,c0325
###############################################################################
# APPLICATION FUNCTIONS
###############################################################################
from .. import helpers, juju
from flask import request, Blueprint


applications = Blueprint('applications', __name__)


@applications.route('/<controllername>/<modelname>/<appname>/config', methods=['GET'])
def get_config(controllername, modelname, appname):
    token = juju.authenticate(request.authorization, controllername, modelname)
    response = juju.config(token, appname)
    return helpers.create_response(200, response)
