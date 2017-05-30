# pylint: disable=c0111,c0301, E0611, E0401
#!/usr/bin/env python3
from urllib.parse import unquote
from sojobo_api import app
from pymongo.errors import DuplicateKeyError

################################################################################
# Database Fucntions
################################################################################
def disconnect():
    app.MONGO.close()


################################################################################
# USER FUNCTIONS
################################################################################
def create_user(user_name, ssh_key=None):
    if not user_name in get_all_users():
        user = {'name' : user_name,
                'access': [],
                'ssh_keys': [ssh_key],
                'active': True}
        app.MONGO.db.users.insert_one(user)


def disable_user(user):
    app.MONGO.db.users.update_one(
        {'name' : user},
        {"$set": {'active': False}
        })
    app.MONGO.db.users.update_one(
        {'name' : user},
        {"$set": {'access': []}
        })


def enable_user(user):
    app.MONGO.db.users.update_one(
        {'name' : user},
        {"$set": {'active': True}
        })


def get_user(name):
    result = app.MONGO.db.users.find_one_or_404({'name': unquote(name)})
    return result


def get_user_by_id(user_id):
    result = app.MONGO.db.users.find_one_or_404({'_id': user_id})
    return result


def add_ssh_key(user, ssh_key):
    app.MONGO.db.users.update_one(
        {'name' : user},
        {'$push': {'ssh_keys' : ssh_key}}
        )


def remove_ssh_key(user, ssh_key):
    app.MONGO.db.users.update_one(
        {'name' : user},
        {'$pull': {'ssh_keys' : ssh_key}}
        )


def get_ssh_keys(usr):
    result = app.MONGO.db.users.find_one_or_404({'name': unquote(usr)})
    print(result)
    return result['ssh_keys']


def get_all_users():
    users = app.MONGO.db.users.find()
    result = []
    for user in users:
        result.append(user['name'])
    return result
################################################################################
# CONTROLLER FUNCTIONS
################################################################################
def create_controller(controller_name, c_type):
    try:
        controller = {'name' : controller_name, 'users': [], 'type' : c_type, 'models' : []}
        app.MONGO.db.controllers.insert_one(controller)
        return True
    except DuplicateKeyError:
        return False


def destroy_controller(c_name):
    app.MONGO.db.controllers.delete_one({'name': unquote(c_name)})
    for user in get_all_users():
        remove_controller(c_name, user)

def remove_controller(c_name, username):
    result = app.MONGO.db.users.find_one_or_404({'name': unquote(username)})
    new_access = []
    acc_list = result['access']
    for acc in acc_list:
        if list(acc.keys())[0] == c_name:
            acc_list.remove(acc)
    new_access = acc_list
    app.MONGO.db.users.update_one(
        {'name' : username},
        {'$set': {'access' : new_access}}
        )

def get_controller(c_name):
    result = app.MONGO.db.controllers.find_one_or_404({'name': unquote(c_name)})
    return result


def add_model_to_controller(c_name, m_name):
    model = {}
    model[m_name] = "Model is being deployed"
    app.MONGO.db.controllers.update_one(
        {'name' : c_name},
        {'$push': {'models' : model}
        })


def set_model_state(c_name, m_name, state):
    con = get_controller(c_name)
    new_access = []
    for mod in con['models']:
        if list(mod.keys())[0] == m_name:
            new_mod = {}
            new_mod[m_name] = state
            mod = new_mod
        new_access.append(mod)
    app.MONGO.db.controllers.update_one(
        {'name' : c_name},
        {'$set': {'models' : new_access}}
        )


def check_model_state(c_name, m_name):
    con = get_controller(c_name)
    for mod in con['models']:
        if list(mod.keys())[0] == m_name:
            return mod[m_name]
    return 'error'


def get_controller_access(controller, user):
    result = app.MONGO.db.users.find_one_or_404({'name': unquote(user)})
    for acc in result['access']:
        if list(acc.keys())[0] == controller:
            return acc[controller]['access']


def set_controller_access(controller, user, access):
    result = app.MONGO.db.users.find_one_or_404({'name': unquote(user)})
    new_access = []
    for acc in result['access']:
        if list(acc.keys())[0] == controller:
            acc[controller]['access'] = access
        new_access.append(acc)
    app.MONGO.db.users.update_one(
        {'name' : user},
        {'$set': {'access' : new_access}}
        )


def add_user_to_controller(controller, user, access):
    userobj = get_user(user)
    app.MONGO.db.controllers.update_one(
        {'name' : controller},
        {'$push': {'users' : userobj['_id']}
        })
    app.MONGO.db.users.update_one(
        {'name' : user},
        {'$push': {'access' : {controller : {'access' : access, 'models' : []}}}
        })


def remove_user_from_controller(controller, user):
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


def get_all_controllers():
    controllers = app.MONGO.db.controllers.find()
    result = []
    for controller in controllers:
        result.append(controller['name'])
    return result
################################################################################
# MODEL FUNCTIONS
################################################################################

def delete_model(controller, model):
    users = get_all_users()
    for user in users:
        remove_model(controller, model, user)


def remove_model(controller, model, username):
    result = app.MONGO.db.users.find_one_or_404({'name': unquote(username)})
    new_access = []
    for acc in result['access']:
        if list(acc.keys())[0] == controller:
            models = acc[controller]['models']
            for modelname in models:
                if list(modelname.keys())[0] == model:
                    models.remove(modelname)
            acc[controller]['models'] = models
        new_access.append(acc)
    app.MONGO.db.users.update_one(
        {'name' : username},
        {'$set': {'access' : new_access}}
        )


def get_model_access(controller, model, user):
    result = app.MONGO.db.users.find_one_or_404({'name': unquote(user)})
    for acc in result['access']:
        if list(acc.keys())[0] == controller:
            models = acc[controller]['models']
            for mod in models:
                if list(mod.keys())[0] == model:
                    return mod[model]
    return None


def set_model_access(controller, model, username, access):
    result = app.MONGO.db.users.find_one_or_404({'name': unquote(username)})
    new_access = []
    for acc in result['access']:
        if list(acc.keys())[0] == controller:
            models = acc[controller]['models']
            for modelname in models:
                if list(modelname.keys())[0] == model:
                    models.remove(modelname)
            new_model = {model: access}
            models.append(new_model)
            acc[controller]['models'] = models
        new_access.append(acc)
    app.MONGO.db.users.update_one(
        {'name' : username},
        {'$set': {'access' : new_access}}
        )


def get_models_access(controller, user):
    result = app.MONGO.db.users.find_one_or_404({'name': unquote(user)})
    for acc in result['access']:
        if list(acc.keys())[0] == controller:
            return acc[controller]['models']


def remove_models_access(controller, user):
    result = app.MONGO.db.users.find_one_or_404({'name': unquote(user)})
    new_access = []
    for acc in result['access']:
        if list(acc.keys())[0] == controller:
            acc[controller]['models'] = []
        new_access.append(acc)
    app.MONGO.db.users.update_one(
        {'name' : user},
        {'$set': {'access' : new_access}}
        )

def get_users_model(controller, model):
    users = get_all_users()
    result = []
    for user in users:
        mod_acc = get_model_access(controller, model, user)
        if not mod_acc is None:
            acc = {'user' : user, 'access' : mod_acc}
            result.append(acc)
    return result
