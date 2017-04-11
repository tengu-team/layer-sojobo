# pylint: disable=c0111,c0301
#!/usr/bin/env python3
from bson.json_util import dumps
from urllib.parse import unquote
from sojobo_api.app import MONGO
from pymongo.errors import DuplicateKeyError

################################################################################
# USER FUNCTIONS
################################################################################
def create_user(user_name, ssh_key=None):
    try:
        user = {'name' : user_name,
                'access': {},
                'ssh_keys': [ssh_key],
                'active': True}
        MONGO.db.users.insert_one(user)
        return True
    except DuplicateKeyError:
        return False


def add_ssh_key(user, ssh_key):
    MONGO.db.users.update_one(
        {'name' : user},
        {'$push': {'ssh_keys' : ssh_key}}
        )

def get_model_access(controller, model, user):
    result = dumps(MONGO.db.users.find_one_or_404({'name': unquote(user)}))
    return result['access'][controller]['models'][model]

def get_controller_access(controller, user):
    result = dumps(MONGO.db.users.find_one_or_404({'name': unquote(user)}))
    return result['access'][controller]['access']

def disable_user(user):
    MONGO.db.users.update_one(
        {'name' : user},
        {"$set": {'active': False}
        })

def get_user_id(name):
    result = dumps(MONGO.db.users.find_one_or_404({'name': unquote(name)}))
    return result['_id']
################################################################################
# CONTROLLER FUNCTIONS
################################################################################
def create_controller(controller_name):
    try:
        controller = {'name' : controller_name, 'users': []}
        MONGO.db.controllers.insert_one(controller)
        return True
    except DuplicateKeyError:
        return False


def remove_controller(controller_name):
    MONGO.db.controllers.delete_one({'name': unquote(controller_name)})

def add_user(controller, user, access):
    user_id = get_user_id(user)
    MONGO.db.controllers.update_one(
        {'name' : controller},
        {'$push': {'users' : user_id}
        })
    MONGO.db.users.update_one(
        {'name' : user},
        {'$push': {'access' : {controller : {'access' : access, 'models' : {}}}}
        })

def remove_user(controller, user):
    user_id = get_user_id(user)
    MONGO.db.controllers.update(
        {'name' : controller},
        {'$pull': {'users' : user_id}
        })
################################################################################
# MODEL FUNCTIONS
################################################################################
def create_model():
    return None

def remove_model():
    return None

def set_model_access():
    return None
