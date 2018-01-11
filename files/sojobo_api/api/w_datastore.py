# pylint: disable=c0111,c0301, E0611, E0401, c0103, w0511
#!/usr/bin/env python3
import json
from sojobo_api import settings
import pyArango.connection as pyArango #Via wheelhouse?


################################################################################
#                               DATABASE FUNCTIONS                             #
################################################################################


def get_arangodb_connection():
    """Creates entry point (connection) to work with ArangoDB."""
    url = 'http://' + settings.ARANGO_HOST + ':' + settings.ARANGO_PORT
    connection = pyArango.Connection(arangoURL=url,
                                     username=settings.ARANGO_USER,
                                     password=settings.ARANGO_PASS)
    return connection


def get_sojobo_database():
    """Returns the sojobo database, creates one if it doesn't exist yet."""
    con = get_arangodb_connection()
    if con.hasDatabase("sojobo"):
        return con["sojobo"]
    return con.createDatabase(name="sojobo")


# def get_users_collection():
#     """Returns the 'users' collection, creates one if it doesn't exist yet."""
#     db = get_sojobo_database()
#     if has_collection(db, "users"):
#         return db["users"]
#     return db.createCollection(name="users")


def create_users_collection():
    """Creates the collection 'users' if it doesn't exist yet."""
    db = get_sojobo_database()
    if not has_collection(db, "users"):
        db.createCollection(name="users")


def create_controllers_collection():
    """Creates the collection 'controllers' if it doesn't exist yet."""
    db = get_sojobo_database()
    if not has_collection(db, "controllers"):
        db.createCollection(name="controllers")

# def get_controllers_collection():
#     """Returns the 'controllers' collection, creates one if it doesn't exist yet."""
#     db = get_sojobo_database()
#     if has_collection(db, "controllers"):
#         return db["controllers"]
#     return db.createCollection(name="controllers")


def get_controller_access_collection():
    db = get_sojobo_database()
    if has_collection(db, "controllerAccess"):
        return db["controllerAccess"]
    return db.createCollection(className="Edges", name="controllerAccess")


def has_collection(db, collection_name):
    return collection_name in db.collections


def execute_aql_query(aql, rawResults=False, **bindings):
    """Executes the given AQL query and returns its results."""
    db = get_sojobo_database()
    bind = {}
    for key in bindings:
        bind[key] = bindings[key]
    return db.AQLQuery(aql, rawResults=rawResults, bindVars=bind)


################################################################################
#                                USER FUNCTIONS                                #
################################################################################


def create_user(user_name):
    # Make sure that the collection exists.
    create_users_collection()
    user = {"_key": user_name,
            "name": user_name,
            "ssh-keys": [],
            "credentials": [],
            "state": "pending"}
    aql = "INSERT @user INTO users"
    execute_aql_query(aql, user=user)


def get_user_doc(username):
    """Returns the Document of a user from ArangoDB given the username (key)."""
    aql = 'FOR u IN users FILTER u._key == @username RETURN u'
    return  execute_aql_query(aql, username=username)[0]


def get_user(username):
    aql = 'FOR u IN users FILTER u._key == @username RETURN u'
    return execute_aql_query(aql, rawResults=True, username=username)[0]


def set_user_state(username, state):
    aql = 'UPDATE {_key: @username, state: @state} IN users'
    execute_aql_query(aql, username=username, state=state)


def get_user_state(username):
    aql = 'FOR u IN users FILTER u._key == @username RETURN u.state'
    return  execute_aql_query(aql, rawResults=True, username=username)[0]


def user_exists(username):
    aql = 'FOR u IN users FILTER u._key == @username RETURN u'
    # Returns an empty list if no user is found.
    user = execute_aql_query(aql, username=username)
    return  bool(user)


def update_ssh_keys(username, ssh_keys):
    aql = 'UPDATE {_key: @username, ssh_keys: @ssh} IN users'
    execute_aql_query(aql, username=username, ssh=ssh_keys)


def get_ssh_keys(username):
    # TODO: Test.
    aql = 'FOR u IN users FILTER u._key == @username RETURN u.ssh_keys'
    return  execute_aql_query(aql, rawResults=True, username=username)[0]


def add_credential(username, cred):
    # TODO: Omvormen naar AQL, methode hieronder is een poging.
    user = get_user_doc(username)
    if cred not in user['credentials']:
        user['credentials'].append(cred)
    user.save()


# def add_credential(username, cred):
#     aql = ('UPDATE "users/@username" WITH {'
#            'credentials: PUSH(doc.credentials, @cred, true)'
#            '} IN users')
#     execute_aql_query(aql, username=username, cred=cred)


def remove_credential(username, cred_name):
    # TODO: Omvormen naar AQL.
    user = get_user_doc(username)
    for cred in user['credentials']:
        if cred_name == cred['name']:
            user['credentials'].remove(cred)
    user.save()


def get_credentials(username):
    aql = 'FOR u IN users FILTER u._key == @username RETURN u.credentials'
    return  execute_aql_query(aql, rawResults=True, username=username)[0]


def get_credential_keys(user):
    # TODO: To test.
    return [c['name'] for c in get_credentials(user)]


def get_all_users():
    """Returns a list with all users from the collection 'users'."""
    aql = "FOR u IN users RETURN u"
    return execute_aql_query(aql, rawResults=True)

def get_all_users_keys():
    """Returns a list with all usernames (keys) from the collection 'users'."""
    aql = "FOR u IN users RETURN u._key"
    return execute_aql_query(aql, rawResults=True)



def delete_user(user):
    """Remove user from collection 'users' and from access (edges) collections."""
    con = connect_to_controllers()
    for c_name in con.keys():
        data = json.loads(con.get(c_name))
        if user in data['users']:
            data['users'].remove(user)
            con.set(c_name, json.dumps(data))
    con = connect_to_users()
    con.delete(user)


################################################################################
#                           CONTROLLER FUNCTIONS                               #
################################################################################


def create_controller(controller_name, c_type, region, cred_name):
    """Creates a controller using AQL."""
    create_controllers_collection()
    # TODO: Check if controller with that name already exists. In this layer?
    controller = {
        "_key": controller_name,
        "name": controller_name,
        "state": "accepted",
        "type": c_type,
        "models": [],
        "endpoints": [],
        "uuid": "",
        "ca-cert": "",
        "region": region,
        "default-credential": cred_name}
    aql = "INSERT @controller INTO controllers LET newController = NEW RETURN newController"
    execute_aql_query(aql, controller=controller)


def controller_exists(c_name):
    aql = 'FOR c IN controllers FILTER c._key == @cname RETURN c'
    # Returns an empty list if no controller is found.
    controller = execute_aql_query(aql, cname=c_name)
    return bool(controller)


def get_cloud_controllers(c_type):
    aql = 'FOR c IN controllers FILTER c.type == @cloud RETURN c'
    return execute_aql_query(aql, cloud=c_type)


def get_users_controller(c_name):
    # TODO: Use edge
    """Returns a list with users of given controller."""
    aql = ('FOR c IN controllers '
           'FILTER c._key == @cname '
           'RETURN c.users')
    return execute_aql_query(aql, cname=c_name)


def get_controllers_user(username):
    u_id = "users/" + username
    aql = ('FOR edge IN controllerAccess'
               'FILTER edge._to == @user'
               'LET c ='
                   '(FOR c IN controllers FILTER c._id == edge._from RETURN c)'
               'RETURN MERGE(c)')
    return execute_aql_query(aql, rawResults=True, user=u_id)[0]


def get_controller_doc(c_name):
    """Returns the Document of a user from ArangoDB given the username (key)."""
    aql = 'FOR c IN controllers FILTER c._key == @cname RETURN c'
    return  execute_aql_query(aql, cname=c_name)[0]


def get_controller(c_name):
    aql = 'FOR c IN controllers FILTER c._key == @controller RETURN c'
    return  execute_aql_query(aql, rawResults=True, controller=c_name)[0]


def add_user_to_controller(c_name, username, access):
    """Creates or updates an Edge (relation) between a controller and a user."""
    c_id = "controllers/" + c_name
    u_id = "users/" + username
    aql = ("UPSERT { _from: @controller, _to: @user }"
           "INSERT { _from: @controller, _to: @user, access: @access}"
           "UPDATE { access : @access } in hasAccess")
    execute_aql_query(aql, controller=c_id, user=u_id, access=access)


def set_controller_state(c_name, state, endpoints=None, uuid=None, ca_cert=None):
    # TODO: Erg dat bij error de None values worden gebruikt?
    aql = ('UPDATE @controller WITH {'
           'state: @state,'
           'endpoints: @endpoints,'
           'uuid: @uuid,'
           'ca_cert: @cacert'
           '} IN controllers')
    execute_aql_query(aql, controller=c_name, state=state, endpoints=endpoints,
                      uuid=uuid, cacert=ca_cert)


def destroy_controller(c_name):
    # TODO: Test
    # TODO: Give better name
    # Remove controller from the collection 'controllers'
    aql = 'REMOVE {_key: @controller} IN controllers'
    execute_aql_query(aql, controller=c_name)


def remove_edges_controller_access(c_name):
    #TODO: Test.
    """Removes all Edges from the collection 'controllerAccess' that contain
    the given controller."""
    c_id = "controllers/" + c_name
    aql = ('FOR edge in controllerAccess'
           'FILTER edge._from == @controller'
           'REMOVE edge in controllerAccess')
    execute_aql_query(aql, controller=c_id)


def remove_controller(c_name, user):
    # TODO: Where is this method used?
    con = connect_to_users()
    data = json.loads(con.get(user))
    for controller in data['controllers']:
        if controller['name'] == c_name:
            data['controllers'].remove(controller)
            break
    con.set(user, json.dumps(data))


    def add_model_to_controller(c_name, m_name):
        c_id = "controllers/" + c_name
        aql = ('LET doc = DOCUMENT(@controller)'
               'UPDATE doc WITH {'
               'models: PUSH(doc.models, @model, true)'
               '} IN controllers')
        execute_aql_query(aql, controller=c_id, model=m_name)


def set_model_state(c_name, m_name, state, credential=None, uuid=None):
    # TODO: Opspliten in 3? Set state, set cred, set uuid
    con = connect_to_controllers()
    data = json.loads(con.get(c_name))
    for model in data['models']:
        if model['name'] == m_name:
            model['state'] = state
            model['credential'] = credential
            if uuid:
                model['uuid'] = uuid
            break
    con.set(c_name, json.dumps(data))


def check_model_state(m_name):
    # TODO: To test
    aql = ('FOR m IN models '
           'FILTER m._key == @model '
           'RETURN m.state')
    return execute_aql_query(aql, rawResults=True, model=m_name)[0]


def get_controller_access(c_name, username):
    # TODO: Test.
    c_id = "controllers/" + c_name
    u_id = "users/" + username
    aql = ('FOR edge in controllerAccess',
           'FILTER edge._from == @controller'
           'FILTER edge._to == @user'
           'RETURN edge.access')
    return execute_aql_query(aql, rawResults=True, controller=c_id, user=u_id)[0]


def set_controller_access(c_name, username, access):
    # TODO: Test
    c_id = "controllers/" + c_name
    u_id = "users/" + username
    aql = ('FOR edge in controllerAccess',
           'FILTER edge._from == @controller'
           'FILTER edge._to == @user'
           'UPDATE edge WITH { access: @access } IN controllerAccess')
    return execute_aql_query(aql, controller=c_id, user=u_id, access=access)[0]


def get_controller_users(c_name):
    data = get_controller(c_name)
    return data['users']

def get_default_credential(c_name):
    controller = get_controller(c_name)
    return controller["default-credential"]

def get_all_controllers():
    #TODO: Test
    create_controllers_collection()
    aql = 'FOR c in controllers RETURN c._key'
    return execute_aql_query(aql, rawResults=True)


# def get_all_models(c_name):
#     # TODO: Test
#     aql = ('FOR c in controllers'
#            'FILTER c._key == @controller'
#            'RETURN c.models')
#     return execute_aql_query(aql, rawResults=True, controller=c_name)

def get_all_models(c_name):
    # TODO: Test
    controller = get_controller(c_name)
    return controller["models"]


################################################################################
# MODEL FUNCTIONS
################################################################################


def delete_model(controller, model):
    con = connect_to_controllers()
    data = json.loads(con.get(controller))
    for mod in data['models']:
        if mod['name'] == model:
            data['models'].remove(mod)
            break
    con.set(controller, json.dumps(data))
    for user in get_all_users():
        remove_model(controller, model, user)


def remove_model(controller, model, user):
    con = connect_to_users()
    data = json.loads(con.get(user))
    for contr in data['controllers']:
        if contr['name'] == controller:
            for mod in contr['models']:
                if mod['name'] == model:
                    contr['models'].remove(mod)
                    break
            break
    con.set(user, json.dumps(data))



def get_model_access(modelname, username):
    # TODO: Test.
    m_id = "models" + modelname
    u_id = "users/" + username
    aql = ('FOR edge in modelAccess',
           'FILTER edge._from == @model'
           'FILTER edge._to == @user'
           'RETURN edge.access')
    return execute_aql_query(aql, rawResults=True, model=m_id, user=u_id)[0]


def set_model_access(controller, model, user, access):
    con = connect_to_users()
    data = json.loads(con.get(user))
    acces_set = False
    for contr in data['controllers']:
        if contr['name'] == controller:
            for mod in contr['models']:
                if model == mod['name']:
                    mod['access'] = access
                    acces_set = True
    if not acces_set:
        for contr in data['controllers']:
            if contr['name'] == controller:
                contr['models'].append({'name': model, 'access': access})
    con.set(user, json.dumps(data))


def get_models_access(controller, user):
    data = get_user_doc(user)
    for con in data['controllers']:
        if con['name'] == controller:
            return con['models']


def remove_models_access(controller, user):
    con = connect_to_users()
    data = json.loads(con.get(user))
    for con in data['controllers']:
        if con['name'] == controller:
            con['models'] = []
            break
    con.set(user, json.dumps(data))


def get_model(controller, model):
    data = get_controller(controller)
    for mod in data['models']:
        if mod['name'] == model:
            return mod


def get_users_model(controller, model):
    return [u for u in get_all_users() if get_model_access(controller, model, u) is not None]
