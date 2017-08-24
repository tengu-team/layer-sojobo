# Copyright (C) 2017  Qrama
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# pylint: disable=c0111,c0301
###############################################################################
# ERROR FUNCTIONS
###############################################################################
def invalid_data():
    return 400, 'The request does not have all the required data or the data is not in the right format.'


def invalid_input():
    return 400, 'Only lowercase letters, digits and hyphens are allowed'


def invalid_access(access):
    return 400, 'This access level does not exist: {}'.format(access)


def invalid_series():
    return 400, 'The series is not supported'


def invalid_option(option):
    return 400, 'Invalid option given, {} does not exist'.format(option)


def invalid_controller(controller):
    return 400, 'This type of controller is not supported -- {}. Contact Qrama for support'.format(controller)


def no_access(item):
    return 401, 'You do not have access to this {}'.format(item)


def unauthorized():
    return 403, 'You do not have permission to use the API'


def does_not_exist(item):
    return 404, 'The {} does not exist!'.format(item)


def key_does_not_exist(key):
    return 400, 'KeyError was raised! The following keys was not found: {}'.format(key)


def no_permission():
    return 405, 'You do not have permission to perform this operation!'


def already_exists(item):
    return 409, 'The {} already exists!'.format(item)


def cmd_error(message):
    return 500, message
