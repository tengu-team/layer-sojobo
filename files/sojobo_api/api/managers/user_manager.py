'''
.. module: user_manager
'''
from subprocess import Popen
from sojobo_api import settings
from sojobo_api.api.storage import w_datastore as datastore


class UserObject(object):

    def __init__(self, username, password, juju_username,
                 controller_access=None, model_access=None, company=None,
                 company_admin=None, ssh_keys=None, credentials=None):
        """ This will create a user Object

        :param str username: The username used to login to the Tengu
            environment.
        :param str password: The pasword used to login to the Tengu
            environment.
        :param str juju_username: The username as it is known by JUJU, not the
            same as the username to log in.
        :param str controller_access: The access level on a given
            controller(optional).
        :param str model_access: The access level on a given model(optional).
        :param str company: The name of the company, the user belongs to
            (optional).
        :param bool company_admin: True if a user is a company admin(optional).
        :param list ssh_keys: A list of a user's ssh keys (optional).
        :param list credentials: A list of a user's credentials (optional).
        """
        self.username = username
        self.password = password
        self.juju_username = juju_username
        self.controller_access = controller_access
        self.model_access = model_access
        self.company = company
        self.company_access = company_admin
        self.ssh_keys = ssh_keys
        self.credentials = credentials


def change_user_password(juju_username, new_password, controller_name):
    """
    This function will change the user his password on the given controller.

    :param str username: The username as it is known by JUJU, not the same as
        the username to log in.
    :param str new_password: The new password for the provided user.
    :param str controller_name: The name of the controller where
        the password needs to be changed
    """
    Popen(["python3",
           "{}/scripts/change_password.py".format(settings.SOJOBO_API_DIR),
           controller_name, juju_username, new_password])


def add_user_to_controller(username, juju_username, password, controller_key):
    '''
    This function will add a user to a certain controller.

    :param str username: The username used to login to the Tengu
        environment.
    :param str password: The pasword used to login to the Tengu
        environment.
    :param str juju_username: The username as it is known by JUJU, not the
        same as the username to log in
    :param str controller_key: The unique hash generated from company name and
    provided controller name
    '''
    Popen(["python3",
           "{}/scripts/add_user_to_controller.py".format(
                settings.SOJOBO_API_DIR),
           username,
           password,
           juju_username,
           controller_key])


def remove_user_from_controller(username, controller_key):
    '''
    This function will remove a user from a certain controller.

    :param str username: The username used to login to the Tengu
        environment.
    :param str controller_key: The unique hash generated from company name and
    provided controller name
    '''
    Popen(["python3",
           "{}/scripts/remove_user_from_controller.py".format(
                settings.SOJOBO_API_DIR),
           username,
           controller_key])


def user_exists(username):
    '''
    This function will check if a user already exists or not.

    :param str username: The username used to login to the Tengu
        environment.
    '''
    return datastore.user_exists(username)
