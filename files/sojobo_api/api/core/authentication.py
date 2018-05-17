from juju.controller import Controller
from juju.errors import JujuAPIError
from juju.model import Model

from sojobo_api import settings
from sojobo_api.api import utils, w_juju as juju
from sojobo_api.api.managers import (
    controller_manager,
    user_manager,
    model_manager
    )
from sojobo_api.api.core import w_errors as errors


async def authenticate(api_key, user, controller=None, model=None):
    error = errors.unauthorized()
    if not user.username:
        raise ValueError(error[0], error[1])
    if api_key == settings.API_KEY:
        if not controller and not model:
            if check_if_admin(user, company=user.company):
                await utils.connect_to_random_controller(user)
                return True
            if len(controller_manager.get_all_controllers(
                    company=user.company)) == 0:
                raise ValueError(error[0], error[1])
            else:
                await utils.connect_to_random_controller(user)
                return True
        try:
            juju.check_controller_state(controller, user)
            # user_manager.check_user_state(user)
            if user.controller_access:
                if controller and not model:
                    controller_connection = Controller()
                    await controller_connection.connect(
                                controller.endpoints[0],
                                user.juju_username,
                                user.password,
                                controller.cacert)
                    return controller_connection
                elif model:
                    model_manager.check_model_state(model)
                    model_connection = Model()
                    await model_connection.connect(
                                controller.endpoints[0],
                                model.uuid,
                                user.juju_username,
                                user.password,
                                controller.cacert)
                    return model_connection
            elif check_if_admin(user, company=user.company):
                return True
            elif controller.state == 'ready':
                await utils.connect_to_random_controller(user)
                user_manager.add_user_to_controllers(
                            user.username,
                            user.juju_username,
                            user.password,
                            user.company)
                raise ValueError(409, ('User {} is being added '
                                       'to the {} environment').format(
                                       user.name, controller.name))
        except JujuAPIError:
            raise ValueError(error[0], error[1])
    else:
        raise ValueError(error[0], error[1])


def check_if_admin(user, company=None):
    if user.username == settings.JUJU_ADMIN_USER and \
            user.password == settings.JUJU_ADMIN_PASSWORD:
        return True
    else:
        return check_if_company_admin(user, company)


def check_if_company_admin(user, company):
    if not company:
        return False
    if user.company == company and user.company_admin:
        return True
