# !/usr/bin/env python3
# Copyright (C) 2016  Qrama
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


def no_permission():
    return 403, 'You do not have permission to perform this operation!'


def no_user():
    return 400, 'The user does not exist!'


def no_app():
    return 400, 'The application does not exist!'


def no_machine():
    return 400, 'The machine does not exist!'
