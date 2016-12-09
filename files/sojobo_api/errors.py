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
