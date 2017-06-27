# pylint: disable=c0111,c0301, E0611, E0401
#!/usr/bin/env python3
import redis
from sojobo_api import settings

################################################################################
# Database Fucntions
################################################################################
def connect_to_controllers():
    con = redis.StrictRedis(host=settings.REDIS_HOST, port=settings.REDIS_PORT, db=10)
    return con

def connect_to_users():
    con = redis.StrictRedis(host=settings.REDIS_HOST, port=settings.REDIS_PORT, db=11)
    return con


################################################################################
# USER FUNCTIONS
################################################################################
def create_user(user_name, ssh_key=None):
    if not user_name in get_all_users():
        user = {'name' : user_name,
                'access': [],
                'ssh_keys': [ssh_key],
                'active': True}
        con = connect_to_users()
        con.set(user_name, user)

def disable_user(user):
    con = connect_to_users()
    data = con.get(user)
    data['active'] = False
    data['access'] = []
    con.set(user, data)

def enable_user(user):
    con = connect_to_users()
    data = con.get(user)
    data['active'] = True
    con.set(user, data)

def get_user(user):
    con = connect_to_users()
    return con.get(user)

def add_ssh_key(user, ssh_key):
    con = connect_to_users()
    data = con.get(user)
    keys = data['ssh_keys']
    keys.append(ssh_key)
    data['ssh_keys'] = keys
    con.set(user, data)

def remove_ssh_key(user, ssh_key):
    con = connect_to_users()
    data = con.get(user)
    keys = data['ssh_keys']
    if ssh_key in keys:
        keys.remove(ssh_key)
    data['ssh_keys'] = keys
    con.set(user, data)


def get_ssh_keys(user):
    con = connect_to_users()
    data = con.get(user)
    return data['ssh_keys']


def get_all_users():
    con = connect_to_users()
    return con.keys()
################################################################################
# CONTROLLER FUNCTIONS
################################################################################
def create_controller(controller_name, c_type):
    con = connect_to_controllers()
    if controller_name in con.keys():
        return False
    else:
        controller = {'name' : controller_name, 'users': [], 'type' : c_type, 'models' : []}
        con.set(controller_name, controller)
        return True

def destroy_controller(c_name):
    con = connect_to_controllers()
    con.delete(c_name)
    for user in get_all_users():
        remove_controller(c_name, user)

def remove_controller(c_name, username):
    con = connect_to_users()
    data = con.get(username)
    acc_list = data['access']
    for acc in acc_list:
        if list(acc.keys())[0] == c_name:
            acc_list.remove(acc)
    data['access'] = acc_list
    con.set(username, data)

def get_controller(c_name):
    con = connect_to_controllers()
    return con.get(c_name)


def add_model_to_controller(c_name, m_name):
    model = {}
    model[m_name] = "Model is being deployed"
    con = connect_to_controllers()
    controller = con.get(c_name)
    model_list = controller['models']
    model_list.append(model)
    controller['models'] = model_list
    con.set(c_name, controller)


def set_model_state(c_name, m_name, state):
    con = connect_to_controllers()
    controller = con.get(c_name)
    new_models = []
    for mod in controller['models']:
        if list(mod.keys())[0] == m_name:
            new_mod = {}
            new_mod[m_name] = state
            mod = new_mod
        new_models.append(mod)
    controller['models'] = new_models
    con.set(c_name, controller)


def check_model_state(c_name, m_name):
    con = get_controller(c_name)
    for mod in con['models']:
        if list(mod.keys())[0] == m_name:
            return mod[m_name]
    return 'error'


def get_controller_access(c_name, user):
    result = get_user(user)
    for acc in result['access']:
        if list(acc.keys())[0] == c_name:
            return acc[c_name]['access']


def set_controller_access(c_name, user, access):
    con = connect_to_users()
    data = con.get(user)
    new_access = []
    for acc in data['access']:
        if list(acc.keys())[0] == c_name:
            acc[c_name]['access'] = access
        new_access.append(acc)
    con.set(c_name, new_access)


def add_user_to_controller(c_name, user, access):
    con = connect_to_controllers()
    data = con.get(c_name)
    users = data['users']
    users.append(user)
    data['users'] = users
    con.set(c_name, data)
    con2 = connect_to_users()
    data2 = con.get(user)
    new_access = data['access']
    new_cont= {c_name:{'access' : access, 'models' : []}}
    new_access.append(new_cont)
    data2['access'] = new_access
    con2.set(user, data2)

def remove_user_from_controller(c_name, user):
    con = connect_to_controllers()
    data = con.get(c_name)
    users = data['users']
    if user in users:
        users.remove(user)
    data['users'] = users
    con.set(c_name, data)


def get_controller_users(c_name):
    con = connect_to_controllers()
    data = con.get(c_name)
    result = []
    for user in data['users']:
        user = get_user(user)
        result.append(user)
    return result


def get_all_controllers():
    con = connect_to_controllers()
    return con.keys()
################################################################################
# MODEL FUNCTIONS
################################################################################

def delete_model(controller, model):
    users = get_all_users()
    for user in users:
        remove_model(controller, model, user)


def remove_model(controller, model, username):
    con = connect_to_users()
    data = con.get(username)
    new_access = []
    for acc in data['access']:
        if list(acc.keys())[0] == controller:
            models = acc[controller]['models']
            for modelname in models:
                if list(modelname.keys())[0] == model:
                    models.remove(modelname)
            acc[controller]['models'] = models
        new_access.append(acc)
    data['access'] = new_access
    con.set(username, data)


def get_model_access(controller, model, user):
    result = get_user(user)
    for acc in result['access']:
        if list(acc.keys())[0] == controller:
            models = acc[controller]['models']
            for mod in models:
                if list(mod.keys())[0] == model:
                    return mod[model]
    return None


def set_model_access(controller, model, username, access):
    con = connect_to_users()
    data = con.get(username)
    new_access = []
    for acc in data['access']:
        if list(acc.keys())[0] == controller:
            models = acc[controller]['models']
            for modelname in models:
                if list(modelname.keys())[0] == model:
                    models.remove(modelname)
            new_model = {model: access}
            models.append(new_model)
            acc[controller]['models'] = models
        new_access.append(acc)
    data['access'] = new_access
    con.set(username, data)


def get_models_access(controller, user):
    result = get_user(user)
    for acc in result['access']:
        if list(acc.keys())[0] == controller:
            return acc[controller]['models']


def remove_models_access(controller, username):
    con = connect_to_users()
    data = con.get(username)
    new_access = []
    for acc in data['access']:
        if list(acc.keys())[0] == controller:
            acc[controller]['models'] = []
        new_access.append(acc)
    data['access'] = new_access
    con.set(username, data)

def get_users_model(controller, model):
    users = get_all_users()
    result = []
    for user in users:
        mod_acc = get_model_access(controller, model, user)
        if not mod_acc is None:
            acc = {'user' : user, 'access' : mod_acc}
            result.append(acc)
    return result
