# pylint: disable=c0111,c0301,c0325
###############################################################################
# MODEL FUNCTIONS
###############################################################################
import helpers
from .. import juju


def create(request):
    data = request.form
    token = juju.authenticate(request.authorization, data['modelname'])
    if juju.model_exists(token):
        response = {'message': 'The model already exists'}
    else:
        juju.create_model(token, data['ssh-keys'])
        response = {'model-name': token.modelname,
                    'model-fullname': token.fqmodelname,
                    'gui-url': juju.get_gui_url(token)}
    return helpers.create_response(200, response)


def delete(request):
    return None


def status(request, modelname):
    data = request.args
    token = juju.authenticate(request.authorization, modelname)
    response = juju.status(token)
    return helpers.create_response(200, response)


def get_config(request, modelname, appname):
    token = juju.authenticate(request.authorization, modelname)
    response = juju.config(token, appname)
    return helpers.create_response(200, response)
