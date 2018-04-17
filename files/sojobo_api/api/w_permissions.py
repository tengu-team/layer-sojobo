#!/usr/bin/env python3

from sojobo_api.api import w_datastore
from sojobo_api import settings

"""
This module has a static dictionary with each call and its required access levels.
It is used to check if a user has the rights to perform certain actions.
"""


permissions = {
	"/bundles/types": {
		"get": {
			"c_access": ["admin", "company_admin", "superuser", "add-model", "login"]
		},
		"post": {
			"c_access": ["admin", "company_admin", "superuser", "add-model", "login"]
		},
		"put": {
			"c_access": ["admin"] #TODO change to allow for company_admin, when functionality is included
		}
	},
	"/controllers/controller": {
		"get": {
			"c_access": ["admin", "company_admin", "superuser"]
		},
		"del": {
			"c_access": ["admin", "company_admin"] #TODO: Update wiki
		}
	},
	"/controllers/controller/models": {
		"get": {
			"c_access": ["admin", "company_admin", "superuser", "add-model", "login"]
		},
		"post": {
			"c_access": ["admin", "company_admin", "superuser", "add-model"]
		}
	},
	"/controllers/controller/models/model": {
		"get": {
			"m_access": ["admin", "write", "read"]
		},
		"post": {
			"m_access": ["admin", "write"]
		},
		"del": {
			"m_access": ["admin"]
		}
	},
	"/controllers/controller/models/model/applications": {
		"get": {
			"m_access": ["admin", "write", "read"]
		},
		"post": {
			"m_access": ["admin", "write"]
		}
	},
	"/controllers/controller/models/model/applications/application": {
		"get": {
			"m_access": ["admin", "write", "read"]
		},
		"put": {
			"m_access": ["admin", "write"]
		},
		"del": {
			"m_access": ["admin", "write"]
		}
	},
	"/controllers/controller/models/model/applications/application/config": {
		"get": {
			"m_access": ["admin", "write", "read"]
		},
		"put": {
			"m_access": ["admin", "write"]
		}
	},
	"/controllers/controller/models/model/machines": {
		"get": {
			"m_access": ["admin", "write", "read"]
		},
		"post": {
			"m_access": ["admin", "write"]
		}
	},
	"/controllers/controller/models/model/machines/machine": {
		"get": {
			"m_access": ["admin", "write", "read"]
		},
		"del": {
			"m_access": ["admin", "write"]
		}
	},
	"/controllers/controller/models/model/applications/application/units": {
		"get": {
			"m_access": ["admin", "write", "read"]
		},
		"post": {
			"m_access": ["admin", "write"]
		}
	},
	"/controllers/controller/models/model/applications/application/units/unitnumber": {
		"get": {
			"m_access": ["admin", "write", "read"]
		},
		"del": {
			"m_access": ["admin", "write"]
		}
	},
	"/controllers/controller/models/model/relations": {
		"get": {
			"m_access": ["admin", "write", "read"]
		},
		"put": {
			"m_access": ["admin", "write"]
		}
	},
	"/controllers/controller/models/model/relations/application": {
		"get": {
			"m_access": ["admin", "write", "read"]
		}
	},
	"/controllers/controller/models/model/relations/app1/app2": {
		"del": {
			"m_access": ["admin", "write"]
		}
	},
	"/users/user": {
		"get": {
			"c_access": ["admin", "company_admin", "superuser"]
		},
		"put": {
			"c_access": ["admin", "company_admin", "superuser"]
		},
		"del": {
			"c_access": ["admin", "company_admin"]
		},
	},
	"/users/user/ssh-keys": {
		"get": {
			"c_access": ["admin", "company_admin", "superuser"]
		},
		"put": {
			"c_access": ["admin", "company_admin", "superuser"]
		}
	},
	"/users/user/credentials": {
		"get": {
			"c_access": ["admin", "company_admin", "superuser"]
		},
		"post": {
			"c_access": ["admin", "company_admin", "superuser"]
		},
		"del": {
			"c_access": ["admin", "company_admin", "superuser"]
		},
	},
    "/users/user/controllers/controller": {
		"get": {
			"c_access": ["admin", "company_admin", "superuser"]
		},
        "put": {
			"c_access": ["admin", "company_admin"]
		}
	},
    "/users/user/controllers/controller/models": {
		"get": {
			"c_access": ["admin", "company_admin", "superuser"]
		},
        "put": {
			"c_access": ["admin", "company_admin", "superuser"]
		}
	},
    "/users/user/controllers/controller/models/model": {
		"get": {
			"c_access": ["admin", "company_admin", "superuser"],
            "m_access": ["admin"]
		}
	}
}


def c_authorize(controller_connection_info, resource, method):
    controller_access = controller_connection_info['c_access']
    allowed_access_levels = permissions[resource][method]['c_access']
    return controller_access in allowed_access_levels


def m_authorize(model_connection_info, resource, method):
    model_access = model_connection_info['m_access']
    allowed_access_levels = permissions[resource][method]['m_access']
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
