# pylint: disable=c0111,c0301,c0325,w0406
###############################################################################
# APPLICATION FUNCTIONS
###############################################################################
from flask import request, Blueprint
from .. import helpers, juju


APPLICATIONS = Blueprint('applications', __name__)


@APPLICATIONS.route('/<controllername>/<modelname>/<appname>/config', methods=['GET'])
def get_config(controllername, modelname, appname):
    token = juju.authenticate(request.authorization, controllername, modelname)
    response = juju.config(token, appname)
    return helpers.create_response(200, response)
