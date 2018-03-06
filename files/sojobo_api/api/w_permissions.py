#!/usr/bin/env python3

from sojobo_api.api import w_juju

"""
This module has a static dictionary with each call and its required access levels.
It is used to check if a user has the rights to perform certain actions.
"""


permissions = {
	"/controllers/controller": {
		"get": {
			"c_access": ["tengu_admin", "company_admin", "superuser"]
		},
		"del": {
			"c_access": ["tengu_admin", "company_admin"] #TODO: Update wiki
		}
	},
	"/controllers/controller/models": {
		"post": {
			"c_access": ["tengu_admin", "company_admin", "superuser", "add-model"]
		}
	},
	"/controllers/controller/models/model": {
		"post": {
			"m_access": ["admin", "write"]
		},
		"del": {
			"m_access": ["admin"]
		}
	},
	"/controllers/controller/models/model/applications": {
		"post": {
			"m_access": ["admin", "write"]
		}
	},
	"/controllers/controller/models/model/applications/application": {
		"put": {
			"m_access": ["admin", "write"]
		},
		"del": {
			"m_access": ["admin", "write"]
		}
	},
	"/controllers/controller/models/model/applications/application/config": {
		"put": {
			"m_access": ["admin", "write"]
		}
	},
	"/controllers/controller/models/model/machines": {
		"post": {
			"m_access": ["admin", "write"]
		}
	},
	"/controllers/controller/models/model/machines/machine": {
		"del": {
			"m_access": ["admin", "write"]
		}
	},
	"/controllers/controller/models/model/applications/application/units": {
		"post": {
			"m_access": ["admin", "write"]
		}
	},
	"/controllers/controller/models/model/applications/application/units/unit": {
		"del": {
			"m_access": ["admin", "write"]
		}
	},
	"/controllers/controller/models/model/relations": {
		"put": {
			"m_access": ["admin", "write"]
		}
	},
	"/controllers/controller/models/model/relations/app1/app2": {
		"del": {
			"m_access": ["admin", "write"]
		}
	},
	"/users/user": {
		"get": {
			"c_access": ["tengu_admin", "company_admin", "superuser"]
		}
	},
    "/users/user/controllers/controller": {
		"get": {
			"c_access": ["tengu_admin", "company_admin", "superuser"]
		},
        "put": {
			"c_access": ["tengu_admin", "company_admin", "superuser"]
		}
	},
    "/users/user/controllers/controller/models": {
		"get": {
			"c_access": ["tengu_admin", "company_admin", "superuser"]
		},
        "put": {
			"c_access": ["tengu_admin", "company_admin", "superuser"]
		}
	},
    "/users/user/controllers/controller/models/model": {
		"get": {
			"c_access": ["tengu_admin", "company_admin", "superuser"],
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


def superuser_authorize(user_info, resource_user):
	return w_juju.has_superuser_access_over_user(user_info['name'], resource_user)
