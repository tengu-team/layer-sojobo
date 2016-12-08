# pylint: disable=c0111,c0301,c0325,w0406
###############################################################################
# MODEL FUNCTIONS
###############################################################################
from flask import request, Blueprint
from .. import helpers, juju


MODELS = Blueprint('models', __name__)


@MODELS.route('/create', methods=['POST'])
def create():
    data = request.form
    try:
        token = juju.authenticate(data['api_key'], request.authorization, data['controller'])
        model = data['model']
        if juju.model_exists(token, model):
            code, response = 200, 'The model already exists'
        else:
            if token.c_access == 'add-model' or token.c_access == 'superuser':
                juju.create_model(token, model, data.get('ssh-keys', None))
                code, response = 200, {'model-name': token.m_name,
                                       'model-fullname': token.m_shared_name(),
                                       'gui-url': juju.get_gui_url(token)}
            else:
                code, response = 403, 'You do not have permission to add models to this controller!'
    except KeyError:
        code, response = helpers.invalid_data()
    return helpers.create_response(code, {'message': response})


@MODELS.route('/delete', method=['DELETE'])
def delete():
    data = request.form
    try:
        token = juju.authenticate(data['api_key'], request.authorization, data['controller'], data['model'])
        if token.m_access == 'admin':
            juju.delete_model(token)
            code, response = 200, 'The model has been destroyed'
        else:
            code, response = 403, 'You do not have permission to remove this model!'
    except KeyError:
        code, response = helpers.invalid_data()
    return helpers.create_response(code, {'message': response})


@MODELS.route('/addsshkey', method=['PUT'])
def add_ssh_key():
    data = request.form
    try:
        token = juju.authenticate(data['api_key'], request.authorization, data['controller'], data['model'])
        if token.m_access == 'admin':
            juju.add_ssh_key(token, data['ssh_key'])
            code, response = 200, 'The ssh-key has been added'
        else:
            code, response = 403, 'You do not have permission to add ssh-keys to this model'
    except KeyError:
        code, response = helpers.invalid_data()
    return helpers.create_response(code, {'message': response})


@MODELS.route('/removesshkey', method=['PUT'])
def remove_ssh_key():
    data = request.format
    try:
        token = juju.authenticate(data['api_key'], request.authorization, data['controller'], data['model'])
        if token.m_access == 'admin':
            juju.remove_ssh_key(token, data['ssh_key'])
            code, response = 200, 'The ssh-key has been removed'
        else:
            code, response = 403, 'You do not have permission to remove ssh-keys from this model'
    except KeyError:
        code, response = helpers.invalid_data()
    return helpers.create_response(code, {'message': response})


@MODELS.route('/<controllername>/<modelname>/status', methods=['GET'])
def status(controllername, modelname):
    data = request.args
    token = juju.authenticate(data['api_key'], request.authorization, controllername, modelname)
    try:
        if token.m_access:
            code, response = 200, juju.model_status(token)
        else:
            code, response = 403, 'You do not have permission to see this model'
    except KeyError:
        code, response = helpers.invalid_data()
    return helpers.create_response(code, response)
