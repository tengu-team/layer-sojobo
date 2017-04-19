# pylint: disable=c0111,c0301
#!/usr/bin/env python3
from urllib.parse import unquote
from bson.json_util import dumps, loads
from sojobo_api import app
from pymongo.errors import DuplicateKeyError

################################################################################
# USER FUNCTIONS
################################################################################
def create_user(user_name, ssh_key=None):
    try:
        user = {'name' : user_name,
                'access': [],
                'ssh_keys': [ssh_key],
                'active': True}
        app.MONGO.db.users.insert_one(user)
        return True
    except DuplicateKeyError:
        return False


def add_ssh_key(user, ssh_key):
    app.MONGO.db.users.update_one(
        {'name' : user},
        {'$push': {'ssh_keys' : ssh_key}}
        )

def get_model_access(controller, model, user):
    result = app.MONGO.db.users.find_one_or_404({'name': unquote(user)})
    for acc in result['access']:
        if list(acc.keys())[0] == controller:
            models = acc[controller]['models']
            for mod in models:
                if list(mod.keys())[0] == model:
                    return mod[model]

def get_controller_access(controller, user):
    result = app.MONGO.db.users.find_one_or_404({'name': unquote(user)})
    for acc in result['access']:
        if list(acc.keys())[0] == controller:
            return acc[controller]['access']

def disable_user(user):
    app.MONGO.db.users.update_one(
        {'name' : user},
        {"$set": {'active': False}
        })

def get_user(name):
    result = app.MONGO.db.users.find_one_or_404({'name': unquote(name)})
    return result


def get_user_by_id(user_id):
    result = app.MONGO.db.users.find_one_or_404({'_id': user_id})
    return result


def get_all_users():
    users = app.MONGO.db.users.find()
    result = []
    for user in users:
        result.append(user['name'])
    return result
################################################################################
# CONTROLLER FUNCTIONS
################################################################################
def create_controller(controller_name):
    try:
        controller = {'name' : controller_name, 'users': []}
        app.MONGO.db.controllers.insert_one(controller)
        return True
    except DuplicateKeyError:
        return False


def remove_controller(controller_name, user):
    app.MONGO.db.controllers.delete_one({'name': unquote(controller_name)})
    app.MONGO.db.users.update_one(
        {'name' : user},
        {'$pull': {'access' : {controller_name :{}}}
        })


def get_controller(c_name):
    result = app.MONGO.db.controllers.find_one_or_404({'name': unquote(c_name)})
    return result


def get_all_controllers():
    controllers = app.MONGO.db.controllers.find()
    result = []
    for controller in controllers:
        result.append(controller['name'])
    return result


def add_user(controller, user, access):
    userobj = get_user(user)
    app.MONGO.db.controllers.update_one(
        {'name' : controller},
        {'$push': {'users' : userobj['_id']}
        })
    app.MONGO.db.users.update_one(
        {'name' : user},
        {'$push': {'access' : {controller : {'access' : access, 'models' : []}}}
        })


def remove_user(controller, user):
    userobj = get_user(user)
    app.MONGO.db.controllers.update(
        {'name' : controller},
        {'$pull': {'users' : userobj['_id']}
        })

def get_controller_users(controller):
    cont = get_controller(controller)
    result = []
    for user_id in cont['users']:
        user = get_user_by_id(user_id)
        result.append(user)
    return result


################################################################################
# MODEL FUNCTIONS
################################################################################
def create_model(controller, model, username):
    app.MONGO.db.users.update_one(
        {'name' : username},
        {'$push': {'access' : {controller : {'models' : {model : 'admin'}}}}
        })


def remove_model(controller, model, username):
    access = get_model_access(controller, model, username)
    app.MONGO.db.users.update_one(
        {'name' : username},
        {'$pull': {'access' : {controller : {'models' : {model : access}}}}
        })

def set_model_access(controller, model, username, access):
    result = app.MONGO.db.users.find_one_or_404({'name': unquote(username)})
    new_access = []
    for acc in result['access']:
        if list(acc.keys())[0] == controller:
            models = acc[controller]['models']
            new_model = {model : access}
            models.append(new_model)
            acc[controller]['models'] = models
        new_access.append(acc)
    app.MONGO.db.users.update_one(
        {'name' : username},
        {'$set': {'access' : new_access}}
        )
