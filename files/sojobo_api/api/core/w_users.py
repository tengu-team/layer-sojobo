'''
.. module: w_users
'''
from sojobo_api.api.storage import w_datastore as datastore
from sojobo_api.api.managers import user_manager


def change_user_password(username, password):
    '''
    This function will change a user's password on all the controllers that the
    user has access to.

    :param username: The username of the user whose password will be changed
    :type username: str.
    :param password: The user his new password
    :type password: str.
    '''
    user_info = datastore.get_user_info(username)
    juju_username = user_info['juju_username']
    for controller in user_info['controllers']:
        controller_name = controller['name']
        user_manager.change_user_password(juju_username, password,
                                          controller_name)
