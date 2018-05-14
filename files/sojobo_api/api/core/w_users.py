'''
.. module: w_users
'''
import hashlib
from sojobo_api.api import utils
from sojobo_api.api.core import w_errors as errors
from sojobo_api.api.storage import w_datastore as datastore
from sojobo_api.api.managers import user_manager


def create_user(username, password, company):
    if not user_manager.user_exists(username):
        juju_username = 'u{}{}'.format(
                    hashlib.md5(username.encode('utf')).hexdigest(),
                    utils.give_timestamp())
        datastore.add_user_to_controller(username, juju_username, company)
        controllers = datastore.get_ready_controllers(company)
        if len(controllers) == 0:
            datastore.set_user_state(username, 'ready')
        else:
            for controller in controllers:
                controller_key = controller['_key']
                user_manager.add_user_to_controllers(
                    username, juju_username, password, controller_key)
            datastore.set_user_state(username, 'ready')
    else:
        raise ValueError(errors.already_exists('user'))


def delete_user(username, company=None):
    datastore.set_user_state(username, 'deleting')
    controllers = datastore.get_ready_controllers(company)
    for controller in controllers:
        controller_key = controller['_key']
        user_manager.remove_user_from_controller(controller_key)
    datastore.delete_user(username)


def change_user_password(username, password):
    '''
    This function will change a user's password on all the controllers that the
    user has access to.

    :param username: The username of the user whose password will be changed
    :type username: str.
    :param password: The user his new password
    :type password: str.
    '''
    if user_manager.user_exists(username):
        user_info = datastore.get_user_info(username)
        juju_username = user_info['juju_username']
        for controller in user_info['controllers']:
            controller_name = controller['name']
            user_manager.change_user_password(juju_username, password,
                                              controller_name)
    else:
        raise ValueError(errors.does_not_exist('user'))
