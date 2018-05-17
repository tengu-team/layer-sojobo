#!/usr/bin/env python3

from sojobo_api.api.storage import w_datastore
from sojobo_api import settings

"""
This module has a static dictionary with each call and its required access levels.
It is used to check if a user has the rights to perform certain actions.
"""


PERMISSIONS = {
	"/bundles/types": {
		"get": {
			"controller_access": ["admin", "company_admin", "superuser", "add-model", "login"]
		},
		"post": {
			"controller_access": ["admin", "company_admin", "superuser", "add-model", "login"]
		},
		"put": {
			"controller_access": ["admin"] #TODO change to allow for company_admin, when functionality is included
		}
	},
	"/controllers/controller": {
		"get": {
			"controller_access": ["admin", "company_admin", "superuser"]
		},
		"del": {
			"controller_access": ["admin", "company_admin"] #TODO: Update wiki
		}
	},
	"/controllers/controller/models": {
		"get": {
			"controller_access": ["admin", "company_admin", "superuser", "add-model", "login"]
		},
		"post": {
			"controller_access": ["admin", "company_admin", "superuser", "add-model"]
		}
	},
	"/controllers/controller/models/model": {
		"get": {
			"model_access": ["admin", "write", "read"]
		},
		"post": {
			"model_access": ["admin", "write"]
		},
		"del": {
			"model_access": ["admin"]
		}
	},
	"/controllers/controller/models/model/applications": {
		"get": {
			"model_access": ["admin", "write", "read"]
		},
		"post": {
			"model_access": ["admin", "write"]
		}
	},
	"/controllers/controller/models/model/applications/application": {
		"get": {
			"model_access": ["admin", "write", "read"]
		},
		"put": {
			"model_access": ["admin", "write"]
		},
		"del": {
			"model_access": ["admin", "write"]
		}
	},
	"/controllers/controller/models/model/applications/application/config": {
		"get": {
			"model_access": ["admin", "write", "read"]
		},
		"put": {
			"model_access": ["admin", "write"]
		}
	},
	"/controllers/controller/models/model/machines": {
		"get": {
			"model_access": ["admin", "write", "read"]
		},
		"post": {
			"model_access": ["admin", "write"]
		}
	},
	"/controllers/controller/models/model/machines/machine": {
		"get": {
			"model_access": ["admin", "write", "read"]
		},
		"del": {
			"model_access": ["admin", "write"]
		}
	},
	"/controllers/controller/models/model/applications/application/units": {
		"get": {
			"model_access": ["admin", "write", "read"]
		},
		"post": {
			"model_access": ["admin", "write"]
		}
	},
	"/controllers/controller/models/model/applications/application/units/unitnumber": {
		"get": {
			"model_access": ["admin", "write", "read"]
		},
		"del": {
			"model_access": ["admin", "write"]
		}
	},
	"/controllers/controller/models/model/relations": {
		"get": {
			"model_access": ["admin", "write", "read"]
		},
		"put": {
			"model_access": ["admin", "write"]
		}
	},
	"/controllers/controller/models/model/relations/application": {
		"get": {
			"model_access": ["admin", "write", "read"]
		}
	},
	"/controllers/controller/models/model/relations/app1/app2": {
		"del": {
			"model_access": ["admin", "write"]
		}
	},
	"/users/user": {
		"get": {
			"controller_access": ["admin", "company_admin", "superuser"]
		},
		"put": {
			"controller_access": ["admin", "company_admin"]
		},
		"del": {
			"controller_access": ["admin", "company_admin"]
		},
	},
	"/users/user/ssh-keys": {
		"get": {
			"controller_access": ["admin", "company_admin", "superuser"]
		},
		"put": {
			"controller_access": ["admin", "company_admin", "superuser"]
		}
	},
	"/users/user/credentials": {
		"get": {
			"controller_access": ["admin", "company_admin", "superuser"]
		},
		"post": {
			"controller_access": ["admin", "company_admin", "superuser"]
		},
		"del": {
			"controller_access": ["admin", "company_admin", "superuser"]
		},
	},
    "/users/user/controllers/controller": {
		"get": {
			"controller_access": ["admin", "company_admin", "superuser"]
		},
        "put": {
			"controller_access": ["admin", "company_admin"]
		}
	},
    "/users/user/controllers/controller/models": {
		"get": {
			"controller_access": ["admin", "company_admin", "superuser"]
		},
        "put": {
			"controller_access": ["admin", "company_admin", "superuser"]
		}
	},
    "/users/user/controllers/controller/models/model": {
		"get": {
			"controller_access": ["admin", "company_admin", "superuser"],
            "model_access": ["admin"]
		}
	}
}


def authorize(user, resource, method, self_user=None, resource_user=None):
    """Checks if a user is authorized to perform a certain http method on
    a certain resource. F.e. Is the user allowed to create a model?

    :param connection_info: Contains the controller and/or model access of the
    user that is trying to authorize.

    :param resource: The resource that the user tries to perform an action on.

    :param method: The HTTP method (get, put, post, del).

    :param self_user: Calls like changing the password of a user can be done
    by an admin OR the user himself. In the latter case 'self_user' must
    contain the user that is provided in the API call.

    :param resource_user: A superuser is allowed to access and update info of
    other users if they are on the same controller. When 'resource_user' is
    provided there needs to be checked if the authenticated user is at least
    superuser on a controller where resource_user resides. 'resource_user' is
    only needed for User API calls."""

    # Admin has authorization in every situation.
    if user.username == settings.JUJU_ADMIN_USER:
        return True
    elif self_user == user.username:
        return True
    elif user.company and user.company_access:
        return True
    elif user.model_access:
        return model_authorize(user.model_access, resource, method)
    elif user.controller_access:
        return controller_authorize(user.controller_access, resource, method)
    elif resource_user:
        return superuser_authorize(superuser=user.username,
                                   resource_user=resource_user)
    else:
        return False


def controller_authorize(controller_access, resource, method):
    allowed_access_levels = PERMISSIONS[resource][method]['controller_access']
    return controller_access in allowed_access_levels


def model_authorize(model_access, resource, method):
    allowed_access_levels = PERMISSIONS[resource][method]['model_access']
    return model_access in allowed_access_levels


def superuser_authorize(superuser, resource_user):
	"""Checks if there is at least one controller where the given user has superuser
	   access over the resource_user."""
	# A superuser is not allowed to see information about admin user.
	if resource_user == settings.JUJU_ADMIN_USER and superuser != settings.JUJU_ADMIN_USER:
		return False
	else:
		matching_controllers = w_datastore.get_superuser_matching_controllers(superuser, resource_user)
		return bool(matching_controllers)
