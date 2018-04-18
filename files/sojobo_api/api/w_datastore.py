#!/usr/bin/env python3
import hashlib
from sojobo_api import settings
import pyArango.connection as pyArango


###############################################################################
#                               DATABASE FUNCTIONS                            #
###############################################################################
def get_arangodb_connection():
    """Creates entry point (connection) to work with ArangoDB."""
    url = 'http://' + settings.ARANGO_HOST + ':' + settings.ARANGO_PORT
    connection = pyArango.Connection(arangoURL=url,
                                     username=settings.ARANGO_USER,
                                     password=settings.ARANGO_PASS)
    return connection


def execute_aql_query(aql, rawResults=False, **bindings):
    """Executes the given AQL query and returns its results.

    :param rawResults: Is default 'False' and will return ArangoDB object types
    like Documents. If it is 'True' then it will return a simple dict.

    :param bindings: The parameters of the AQL query. F.e. If you have
    one parameter @user in AQL query then this function will look like this:
    execute_aql_query(aql, user='admin').
    If you have two parameters @user and @model then it will look like this:
    execute_aql_query(aql, user='admin', model='testmodel')."""
    connection = get_arangodb_connection()
    db = connection[settings.ARANGO_DB]
    bind = {}
    for key in bindings:
        bind[key] = bindings[key]
    results = db.AQLQuery(aql, rawResults=rawResults, bindVars=bind)
    connection.disconnectSession()
    return list(results)


###############################################################################
#                                USER FUNCTIONS                               #
###############################################################################
def create_user(username, juju_username, company=None):
    user = {"_key": hash_username(username),
            "name": username,
            "juju_username": juju_username,
            "ssh_keys": [],
            "credentials": [],
            "state": "pending"}
    aql = "INSERT @user INTO users"
    execute_aql_query(aql, user=user)
    if company:
        add_user_to_company(username, company)


def user_exists(username):
    u_id = get_user_id(username)
    aql = 'RETURN DOCUMENT(@u_id)'
    user = execute_aql_query(aql, rawResults=True, u_id=u_id)[0]
    return user is not None


def get_user(username):
    """Returns the dict of a user."""
    u_id = get_user_id(username)
    aql = 'RETURN DOCUMENT(@u_id)'
    return execute_aql_query(aql, rawResults=True, u_id=u_id)[0]


def get_all_users():
    aql = "FOR u IN users RETURN u"
    return execute_aql_query(aql, rawResults=True)


def get_user_doc(username):
    # TODO: If credential methods work with AQL then this function
    # becomes obsolete.
    """Returns the Document of a user."""
    aql = 'FOR u IN users FILTER u._key == @username RETURN u'
    return execute_aql_query(aql, username=hash_username(username))[0]


def get_users_info(company=None):
    """Returns info of all the users, including which controllers and models
    that the users have access to."""
    if not company:
        aql = ('FOR u in users '
                   'LET controllers = '
                       '(FOR controller, cEdge IN 1..1 INBOUND u._id controllerAccess '
                           'LET models = '
                               '(FOR model, mEdge in 1..1 INBOUND u._id modelAccess '
                                   'FILTER model._key in controller.models '
                                   'RETURN MERGE(model, {access: mEdge.access})) '
                           'RETURN MERGE(controller, { access: cEdge.access, models: models})) '
                   'RETURN MERGE(u, {controllers: controllers})')
        users = execute_aql_query(aql, rawResults=True)
    else:
        com_id = 'companies/{}'.format(company)
        aql = ('FOR company, comEdge IN 1..1 OUTBOUND @com_id companyAccess '
                   'LET u = DOCUMENT(comEdge._to) '
                   'LET controllers = '
                       '(FOR controller, cEdge IN 1..1 INBOUND u._id controllerAccess '
                           'LET models = '
                               '(FOR model, mEdge in 1..1 INBOUND u._id modelAccess '
                                   'FILTER model._key in controller.models '
                                   'RETURN MERGE(model, {access: mEdge.access})) '
                           'RETURN MERGE(controller, { access: cEdge.access, models: models})) '
                   'RETURN MERGE(u, {controllers: controllers})')
        users = execute_aql_query(aql, rawResults=True, com_id=com_id)
    results = []
    for u in users:
        results.append(u)
    return results


def get_user_info(username):
    """Returns info of the given user, including which controllers and models
    that the user has access to."""
    u_id = get_user_id(username)
    aql = ('LET u = DOCUMENT(@user) '
           'LET com = '
           'FIRST((FOR comEdge IN companyAccess '
                  "FILTER comEdge._to == u._id "
                  "RETURN {company: DOCUMENT(comEdge._from).name, company_access: {admin: comEdge.is_admin}}))"
           'LET controllers = '
                '(FOR controller, cEdge IN 1..1 INBOUND u._id controllerAccess '
                    'LET models = '
                        '(FOR model, mEdge in 1..1 INBOUND u._id modelAccess '
                            'FILTER model._key in controller.models '
                            'RETURN MERGE(model, {access: mEdge.access})) '
                    'RETURN MERGE(controller, { access: cEdge.access, models: models})) '
            'RETURN MERGE(u, {controllers: controllers}, {company: com})')
    result = execute_aql_query(aql, rawResults=True, user=u_id)
    return result[0]


def get_user_state(username):
    u_id = get_user_id(username)
    aql = 'LET u = DOCUMENT(@u_id) RETURN u.state'
    return  execute_aql_query(aql, rawResults=True, u_id=u_id)[0]


def set_user_state(username, state):
    aql = 'UPDATE {_key: @username, state: @state} IN users'
    execute_aql_query(aql, username=hash_username(username), state=state)


def get_ssh_keys(username):
    u_id = get_user_id(username)
    aql = 'LET u = DOCUMENT(@u_id) RETURN u.ssh_keys'
    return  execute_aql_query(aql, rawResults=True, u_id=u_id)


def update_ssh_keys(username, ssh_keys):
    aql = 'UPDATE {_key: @username, ssh_keys: @ssh} IN users'
    execute_aql_query(aql, username=hash_username(username), ssh=ssh_keys)


def delete_user(username):
    """Remove user from collection 'users' and from access collections."""
    remove_user_c_access(username)
    remove_user_m_access(username)
    remove_user_u_col(username)


def remove_user_u_col(username):
    """Removes the user from the collection 'users'."""
    aql = 'REMOVE {_key: @username} IN users'
    execute_aql_query(aql, username=hash_username(username))


def remove_user_c_access(username):
    """Removes every Edge from controllerAccess that contains given user."""
    u_id = get_user_id(username)
    aql = ('FOR edge in controllerAccess '
           'FILTER edge._to == @u_id '
           'REMOVE edge in controllerAccess')
    execute_aql_query(aql, u_id=u_id)


def remove_user_m_access(username):
    """Removes every Edge from modelAccess that contains given user."""
    u_id = get_user_id(username)
    aql = ('FOR edge in modelAccess '
           'FILTER edge._to == @u_id '
           'REMOVE edge in modelAccess')
    execute_aql_query(aql, u_id=u_id)


################################################################################
#                           CREDENTIAL FUNCTIONS                               #
################################################################################
def get_credentials(username):
    u_id = get_user_id(username)
    aql = 'LET u = DOCUMENT(@u_id) RETURN u.credentials'
    return execute_aql_query(aql, rawResults=True, u_id=u_id)[0]


def get_credential_keys(username):
    u_id = get_user_id(username)
    aql = 'LET u = DOCUMENT(@u_id) RETURN u.credentials'
    return execute_aql_query(aql, rawResults=True, u_id=u_id)


def get_credential(username, cred_name):
    c_id = "credentials/{}".format(get_credential_id(username, cred_name))
    aql ='LET u = DOCUMENT(@c_id) RETURN u'
    return execute_aql_query(aql, rawResults=True, c_id=c_id)[0]


def get_credential_id(username, cred_name):
    u_id = get_user_id(username)
    aql =('LET u = DOCUMENT(@u_id) '
          'FOR cred in u.credentials '
          'FILTER cred.name == @cred_name '
          'RETURN cred')
    output = execute_aql_query(aql, rawResults=True, u_id=u_id, cred_name=cred_name)[0]
    return output['key']


def add_credential(username, cred):
    cred['state'] = 'accepted'
    aql = 'INSERT @credential INTO credentials LET newCredential = NEW RETURN newCredential '
    output = execute_aql_query(aql, rawResults=True, credential=cred)[0]
    print(output)
    update_user_credential(username, {'name': cred['name'], 'key': output['_key']})


def update_user_credential(username, cred):
    u_id = get_user_id(username)
    aql = ('LET doc = DOCUMENT(@u_id) '
           'UPDATE doc WITH {'
           'credentials: PUSH(doc.credentials, @credential, true)'
           '} IN users')
    execute_aql_query(aql, u_id=u_id, credential=cred)


def set_credential_ready(username, cred_name):
    c_id = "credentials/{}".format(get_credential_id(username, cred_name))
    aql = ('LET u = DOCUMENT(@c_id) '
           'UPDATE u WITH { '
           'state: "ready"} in credentials')
    execute_aql_query(aql, c_id=c_id)


def remove_credential(username, cred_name):
    c_id = get_credential_id(username, cred_name)
    u_id = get_user_id(username)
    u_aql = 'REMOVE {_key: @c_id} IN credentials'
    execute_aql_query(u_aql, c_id=c_id)
    credential = {'name': cred_name, 'key': c_id}
    aql = ('LET u = DOCUMENT(@u_id) '
           'UPDATE u WITH { '
           'credentials: REMOVE_VALUE(u.credentials, @credential) '
           '} IN users')
    execute_aql_query(aql, u_id=u_id, credential=credential)


###############################################################################
#                           CONTROLLER FUNCTIONS                              #
###############################################################################
def create_controller(controller_name, c_type, region, cred_name):
    controller = {
        "_key": controller_name,
        "name": controller_name,
        "state": "accepted",
        "type": c_type,
        "models": [],
        "endpoints": [],
        "uuid": "",
        "ca_cert": "",
        "region": region,
        "default-credential": cred_name}
    aql = "INSERT @controller INTO controllers LET newController = NEW RETURN newController"
    return execute_aql_query(aql, controller=controller)


def create_manual_controller(name, c_type, url):
    controller = {
        "_key": name,
        "name": name,
        "state": "accepted",
        "type": c_type,
        "models": [],
        "endpoints": [],
        "uuid": "",
        "ca_cert": "",
        "url": url}
    aql = "INSERT @controller INTO controllers LET newController = NEW RETURN newController"
    return execute_aql_query(aql, controller=controller)


def controller_exists(c_name):
    c_id = "controllers/" + c_name
    aql = 'RETURN DOCUMENT("controllers", @c_id)'
    controller = execute_aql_query(aql, rawResults=True, c_id=c_id)[0]
    if controller is None:
        return False
    return True


def get_controller(c_name):
    """Returns the dict of a controller."""
    c_id = "controllers/" + c_name
    aql = 'RETURN DOCUMENT(@c_id)'
    return execute_aql_query(aql, rawResults=True, c_id=c_id)[0]


def get_controller_info(c_name):
    """Returns the info of a controller. This includes the models (and their info)
    and the users that have access to the controller."""
    c_id = "controllers/" + c_name
    aql = ( 'LET c = DOCUMENT(@c_id) '
            'LET models = '
                '(FOR m_key in c.models '
                    'RETURN DOCUMENT(CONCAT("models/", m_key))) '
            'LET users = '
                '(FOR u, cEdge IN 1..1 OUTBOUND @c_id controllerAccess '
                    'RETURN {name: u.name, access: cEdge.access}) '
            'RETURN {name: c.name, state: c.state, type: c.type, '
                    'models: models, users: users}' )
    return execute_aql_query(aql, rawResults=True, c_id=c_id)


def get_all_controllers(company=None):
    if not company:
        aql = 'FOR c in controllers RETURN c'
        return execute_aql_query(aql, rawResults=True)
    else:
        c_id = 'companies/{}'.format(company)
        aql = ('LET com = DOCUMENT(@c_id) '
               'RETURN com.controllers')
        return execute_aql_query(aql, rawResults=True, c_id=c_id)


def get_ready_controllers(company=None):
    if not company:
        aql = 'FOR c in controllers FILTER c.state == "ready" RETURN c'
        return execute_aql_query(aql, rawResults=True)
    else:
        c_id = 'companies/{}'.format(company)
        aql = ('LET com = DOCUMENT(@c_id) '
               'FOR controller in controllers '
               'FILTER controller.name in com.controllers and controller.state == "ready" '
               'RETURN controller')
        return execute_aql_query(aql, rawResults=True, c_id=c_id)


def get_ready_controllers_with_access(username, company=None):
    """Returns a list with ready controllers that the given user has access to."""
    if not company:
        u_id = get_user_id(username)
        aql = ('FOR c, cEdge IN 1..1 INBOUND @u_id controllerAccess '
                    'FILTER c.state == "ready" '
                    'RETURN c')
        return execute_aql_query(aql, rawResults=True, u_id=u_id)
    u_id = get_user_id(username)
    c_id = 'companies/{}'.format(company)
    aql = ('LET com = DOCUMENT(@c_id) '
           'FOR c, cEdge IN 1..1 INBOUND @u_id controllerAccess '
                'FILTER c.state == "ready" '
                'FILTER c.name IN com.controllers '
                'RETURN c')
    return execute_aql_query(aql, rawResults=True, u_id=u_id, c_id=c_id)


def get_ready_controllers_no_access(username, company):
    if not company:
        c_id = 'controllers/login'
        aql = 'RETURN DOCUMENT(@c_id)'
        return execute_aql_query(aql, rawResults=True, c_id=c_id)
    """Returns a list with ready controllers that the given user has no access to."""
    u_id = get_user_id(username)
    c_id = 'companies/{}'.format(company)
    aql = ('LET com = DOCUMENT(@c_id) '
           'LET controllers_with_access = '
               '(FOR c, cEdge IN 1..1 INBOUND @u_id controllerAccess '
                    'RETURN c) '
               'FOR c IN controllers '
                    'FILTER c.state == "ready" '
                    'FILTER c.name IN com.controllers '
                    'FILTER c NOT IN controllers_with_access '
                    'RETURN c')
    return execute_aql_query(aql, rawResults=True, u_id=u_id, c_id=c_id)


def get_keys_controllers(company=None):
    if not company:
        aql = 'FOR c in controllers RETURN c._key'
        return execute_aql_query(aql, rawResults=True)
    else:
        c_id = 'companies/{}'.format(company)
        aql = ('LET com = DOCUMENT(@c_id) '
               'RETURN com.controllers')
        return execute_aql_query(aql, rawResults=True, c_id=c_id)[0]


def get_cloud_controllers(c_type, company=None):
    if not company:
        aql = ('FOR c IN controllers '
               'FILTER c.type == @cloud '
               'FILTER c.state == "ready" '
               'RETURN c')
        return execute_aql_query(aql, rawResults=True, cloud=c_type)
    else:
        c_id = 'companies/{}'.format(company)
        aql = ('LET com = DOCUMENT(@c_id) '
               'FOR  controller in controllers '
               'FILTER controller.name in com.controllers and controller.type == @cloud '
               'RETURN controller ')
        return execute_aql_query(aql, rawResults=True, cloud=c_type, c_id=c_id)


def get_users_controller(c_name):
    """Returns a list with users and access of given controller."""
    c_id = "controllers/" + c_name
    aql = ('FOR u, cEdge IN 1..1 OUTBOUND @c_id controllerAccess '
               'RETURN {name: u.name, juju_username: u.juju_username, access: cEdge.access}')
    return execute_aql_query(aql, rawResults=True, c_id=c_id)


def get_controllers_access(username):
    u_id = get_user_id(username)
    aql = ('FOR c, cEdge IN 1..1 INBOUND @u_id controllerAccess '
             'LET models = '
               '(FOR model, mEdge in 1..1 INBOUND @u_id modelAccess '
                    'FILTER model._key in c.models '
                    'RETURN {name: model.name, '
                            'access: mEdge.access}) '
           'RETURN {name: c.name, access: cEdge.access, models: models, type: c.type}')
    controllers = execute_aql_query(aql, rawResults=True, u_id=u_id)
    # The variable 'controllers' is NOT a list but an iterator so we can not return that.
    # We have to iterate over 'controllers' and add every element to a list because
    # a list is JSON serializable and an iterator is not.
    results = []
    for c in controllers:
        results.append(c)
    return results


def add_user_to_controller(c_name, username, access):
    """Creates or updates an Edge (relation) between a controller and a user."""
    c_id = "controllers/" + c_name
    u_id = get_user_id(username)
    aql = ("UPSERT { _from: @controller, _to: @user }"
           "INSERT { _from: @controller, _to: @user, access: @access}"
           "UPDATE { access : @access } in controllerAccess")
    execute_aql_query(aql, controller=c_id, user=u_id, access=access)


def set_controller_state(c_name, state, endpoints=None, uuid=None, ca_cert=None):
    aql = ('UPDATE @controller WITH {'
           'state: @state,'
           'endpoints: @endpoints,'
           'uuid: @uuid,'
           'ca_cert: @cacert'
           '} IN controllers')
    execute_aql_query(aql, controller=c_name, state=state, endpoints=endpoints,
                      uuid=uuid, cacert=ca_cert)


def destroy_controller(c_name):
    remove_edges_controller_access(c_name)
    remove_models_controller(c_name)
    remove_controller_c_col(c_name)


def remove_controller_c_col(c_name):
    """Removes the controller from the collection 'controllers'."""
    aql = 'REMOVE {_key: @controller} IN controllers'
    execute_aql_query(aql, controller=c_name)


def remove_edges_controller_access(c_name):
    """Removes all Edges from the collection 'controllerAccess' that contain
    the given controller."""
    c_id = "controllers/" + c_name
    aql = ('FOR edge in controllerAccess '
           'FILTER edge._from == @controller '
           'REMOVE edge in controllerAccess')
    execute_aql_query(aql, controller=c_id)


def remove_models_controller(c_name):
    """Remove all models that are from a given controller."""
    c_id = "controllers/" + c_name
    aql = ('LET c = DOCUMENT(@controller) '
           'FOR m_key in c.models '
                'FOR mEdge in modelAccess '
                    'FILTER mEdge._from == CONCAT("models/", m_key) '
                    'REMOVE mEdge in modelAccess '
                'REMOVE {_key: m_key} IN models ')
    execute_aql_query(aql, controller=c_id)


def add_model_to_controller(c_name, m_key):
    c_id = "controllers/" + c_name
    aql = ('LET doc = DOCUMENT(@controller) '
           'UPDATE doc WITH {'
           'models: PUSH(doc.models, @model, true)'
           '} IN controllers')
    execute_aql_query(aql, controller=c_id, model=m_key)


def get_controller_access(c_name, username):
    """Returns the access level that a user has to a controller."""
    c_id = "controllers/" + c_name
    u_id = get_user_id(username)
    aql = ('FOR controller, cEdge IN 1..1 INBOUND @u_id controllerAccess  '
               'FILTER cEdge._from == @c_id '
               'RETURN cEdge.access ')
    return execute_aql_query(aql, rawResults=True, c_id=c_id, u_id=u_id)[0]


def get_controller_and_access(c_name, username):
    """Returns info about the controller AND the access level of the given user
    in one dictionary."""
    c_id = "controllers/" + c_name
    u_id = get_user_id(username)
    aql = ('FOR controller, cEdge IN 1..1 INBOUND @u_id controllerAccess  '
               'FILTER cEdge._from == @c_id '
               'LET models = '
                 '(FOR model, mEdge in 1..1 INBOUND @u_id modelAccess '
                      'FILTER model._key in controller.models '
                      'RETURN {name: model.name, '
                              'access: mEdge.access}) '
               'RETURN {access: cEdge.access, name: controller.name, '
                       'models: models, type: controller.type}')
    return execute_aql_query(aql, rawResults=True, c_id=c_id, u_id=u_id)[0]


def set_controller_access(c_name, username, access):
    c_id = "controllers/" + c_name
    u_id = get_user_id(username)
    aql = ("UPSERT { _from: @c_id, _to: @u_id }"
           "INSERT { _from: @c_id, _to: @u_id, access: @access}"
           "UPDATE { access : @access } in controllerAccess")
    execute_aql_query(aql, c_id=c_id, u_id=u_id, access=access)


def get_superuser_matching_controllers(user, resource_user):
    """Get controllers where the given user has superuser access and where
    the resource_user resides."""
    u_id = get_user_id(user)
    ru_id = get_user_id(resource_user)
    aql = ('FOR controller, cEdge IN 1..1 INBOUND @u_id controllerAccess '
                'FILTER cEdge.access == "superuser" '
                'FOR c, E IN 1..1 INBOUND @ru_id controllerAccess '
                    'FILTER c == controller '
                    'RETURN c')
    return execute_aql_query(aql, rawResults=True, u_id=u_id, ru_id=ru_id)


###############################################################################
#                               MODEL FUNCTIONS                               #
###############################################################################
def create_model(m_key, m_name, state, uuid=''):
    model = {
        "_key": m_key,
        "name": m_name,
        "state": state,
        "uuid": uuid}
    aql = "INSERT @model INTO models LET newModel = NEW RETURN newModel"
    return execute_aql_query(aql, rawResults=True, model=model)


def model_exists(m_key):
    m_id = "models/" + m_key
    aql = 'RETURN DOCUMENT("models", @m_id)'
    model = execute_aql_query(aql, rawResults=True, m_id=m_id)[0]
    if model is None:
        return False
    return True


def get_model(m_key):
    m_id = "models/" + m_key
    aql = 'RETURN DOCUMENT(@m_id)'
    return execute_aql_query(aql, rawResults=True, m_id=m_id)[0]


def get_model_key(c_name, m_name):
    controller = get_controller(c_name)
    for key in controller["models"]:
        model = get_model(key)
        if model["name"] == m_name:
            return key
    return None


def get_all_models(c_name):
    c_id = "controllers/" + c_name
    aql = ('LET c = DOCUMENT(@controller) '
           'FOR m_key in c.models '
                'LET m = DOCUMENT(CONCAT("models/",m_key)) '
                'RETURN m')
    return execute_aql_query(aql, rawResults=True, controller=c_id)


def delete_model(c_name, m_key):
    remove_model_m_col(m_key)
    remove_edges_models_access(m_key)
    remove_model_from_controller(c_name, m_key)


def remove_model_m_col(m_key):
    """Removes the model from the collection 'models'."""
    aql = 'REMOVE {_key: @model} IN models'
    execute_aql_query(aql, model=m_key)


def remove_edges_models_access(m_key):
    """Removes all Edges from the collection 'modelAccess' that contain
    the given model."""
    m_id = "models/" + m_key
    aql = ('FOR edge in modelAccess '
           'FILTER edge._from == @model '
           'REMOVE edge in modelAccess')
    execute_aql_query(aql, model=m_id)


def remove_model_from_controller(c_name, m_key):
    c_id = "controllers/" + c_name
    aql = ('LET doc = DOCUMENT(@controller) '
           'UPDATE doc WITH { '
           'models: REMOVE_VALUE(doc.models, @model) '
           '} IN controllers')
    execute_aql_query(aql, controller=c_id, model=m_key)


def set_model_state(m_key, state, credential=None, uuid=None):
    if not credential and not uuid:
        aql = ('UPDATE @model WITH {'
               'state: @state '
               '} IN models')
        execute_aql_query(aql, model=m_key, state=state)
    else:
        aql = ('UPDATE @model WITH {'
               'state: @state, '
               'credential: @credential, '
               'uuid: @uuid'
               '} IN models')
        execute_aql_query(aql, model=m_key, state=state, credential=credential, uuid=uuid)


def get_model_state(m_key):
    m_id = "models/" + m_key
    aql = ('LET model = DOCUMENT(@m_id) '
           'RETURN model.state')
    return execute_aql_query(aql, rawResults=True, m_id=m_id)[0]


def get_model_access(c_name, m_name, username):
    c_id = "controllers/" + c_name
    u_id = get_user_id(username)
    aql = ('LET c = DOCUMENT(@controller) '
           'FOR model, mEdge in 1..1 INBOUND @user modelAccess '
                'FILTER model._key in c.models '
                'FILTER model.name == @model '
                'RETURN mEdge.access ')
    result = execute_aql_query(aql, rawResults=True, controller=c_id, model=m_name, user=u_id)[0]
    if bool(result):
        return result


def get_model_and_access(m_key, username):
    m_id = "models/" + m_key
    u_id = get_user_id(username)
    aql = ("LET mod = DOCUMENT(@m_id) "
           "LET m_access = "
                "FIRST((FOR m, mEdge IN 1..1 INBOUND @u_id modelAccess "
                    "FILTER mEdge._from == @m_id "
                    "RETURN mEdge.access)) "
           "RETURN {mod, m_access} ")
    return execute_aql_query(aql, rawResults=True, m_id=m_id, u_id=u_id)[0]


def get_models_access(c_name, username):
    u_id = get_user_id(username)
    c_id = "controllers/" + c_name
    aql = ('LET c = DOCUMENT(@controller) '
           'LET models = '
           '(FOR model, mEdge in 1..1 INBOUND @user modelAccess '
           'FILTER model._key in c.models '
           'RETURN {name: model.name, access: mEdge.access}) '
           'RETURN models')
    return execute_aql_query(aql, rawResults=True,
                             controller=c_id, user=u_id)[0]


def set_model_access(m_key, username, access):
    m_id = "models/" + m_key
    u_id = get_user_id(username)
    aql = ("UPSERT { _from: @model, _to: @user }"
           "INSERT { _from: @model, _to: @user, access: @access}"
           "UPDATE { access : @access } in modelAccess")
    execute_aql_query(aql, model=m_id, user=u_id, access=access)


def get_users_model(m_key):
    m_id = "models/" + m_key
    aql = ('FOR u, mEdge IN 1..1 OUTBOUND @m_id modelAccess '
           'RETURN {name: u.name, access: mEdge.access}')
    return execute_aql_query(aql, rawResults=True, m_id=m_id)


def create_workspace_type(workspace_type, price_per_second):
    ws_type = {"_key": workspace_type,
               "price_per_second": price_per_second}
    aql = "INSERT @ws_type INTO workspace_types"
    return execute_aql_query(aql, ws_type=ws_type)


def workspace_type_exists(ws_type):
    ws_type_id = get_workspace_type_id(ws_type)
    aql = 'RETURN DOCUMENT("workspace_types", @ws_type_id)'
    workspace_type = execute_aql_query(aql, rawResults=True, ws_type_id=ws_type_id)[0]
    return workspace_type is not None


def add_edge_between_model_and_workspace_type(m_key, ws_type):
    """Creates an Edge between a model and a workspace type."""
    m_id = get_model_id(m_key)
    ws_type_id = get_workspace_type_id(ws_type)
    aql = ("INSERT { _from: @m_id, _to: @ws_type_id} in modelType")
    execute_aql_query(aql, m_id=m_id, ws_type_id=ws_type_id)


###############################################################################
#                          COMPANY FUNCTIONS                                  #
###############################################################################
def create_company(company_name, uri):
    company = {"_key": company_name,
               "name": company_name,
               "hubspot_uri": uri,
               "controllers": []}
    aql = "INSERT @company INTO companies"
    execute_aql_query(aql, company=company)


def get_company_user(user):
    u_id = get_user_id(user)
    aql = ("FOR user, comEdge in 1..1 INBOUND @u_id companyAccess "
           "FILTER comEdge._to == @u_id "
           "RETURN {company: DOCUMENT(comEdge._from).name, company_access: {is_admin: comEdge.is_admin}}")
    output = execute_aql_query(aql, rawResults=True, u_id=u_id)
    if len(output) > 0:
        return output[0]
    return []


def get_company(company):
    com_id = "companies/" + company
    aql = 'RETURN DOCUMENT(@com_id)'
    return execute_aql_query(aql, rawResults=True, com_id=com_id)[0]


def get_company_admins(company):
    com_id = "companies/" + company
    aql = ("FOR company, comEdge in 1..1 OUTBOUND @com_id companyAccess "
           "FILTER comEdge.is_admin == @is_admin "
           "RETURN DOCUMENT(comEdge._to)")
    return execute_aql_query(aql, rawResults=True, is_admin=True, com_id=com_id)


def add_user_to_company(user, company, admin=False):
    com_id = "companies/" + company
    u_id = get_user_id(user)
    aql = ("UPSERT { _from: @com_id, _to: @u_id }"
           "INSERT { _from: @com_id, _to: @u_id, is_admin: @is_admin} "
           "UPDATE { is_admin : @is_admin } in companyAccess")
    execute_aql_query(aql, com_id=com_id, u_id=u_id, is_admin=admin)


def get_companies():
    aql = 'FOR c in companies RETURN c'
    return execute_aql_query(aql, rawResults=True)


def add_controller_to_company(controller_name, company):
    company_id = "companies/" + company
    aql = ('LET doc = DOCUMENT(@company_id) '
           'UPDATE doc WITH {'
           'controllers: PUSH(doc.controllers, @controller, true)'
           '} IN companies')
    execute_aql_query(aql, controller=controller_name, company_id=company_id)


def upgrade_to_company_admin(company, username):
    u_id = get_user_id(username)
    c_id = "companies/" + company
    aql = ("UPSERT { _from: @c_id, _to: @u_id }"
           "INSERT { _from: @c_id, _to: @u_id, is_admin: @is_admin}"
           "UPDATE { is_admin : @is_admin } in companyAccess")
    execute_aql_query(aql, u_id=u_id, c_id=c_id, is_admin=True)
###############################################################################
#                          CONNECTION FUNCTIONS                               #
###############################################################################
def get_controller_connection_info(username, c_name):
    u_id = get_user_id(username)
    c_id = "controllers/" + c_name
    aql = ("LET user = DOCUMENT(@u_id) "
           "LET controller = DOCUMENT(@c_id) "
           "LET c_access = "
           "FIRST((FOR c, cEdge IN 1..1 INBOUND @u_id controllerAccess "
           "FILTER cEdge._from == @c_id "
           "RETURN cEdge.access)) "
           "LET company = "
           "FIRST((FOR usr, comEdge in 1..1 INBOUND @u_id companyAccess "
           "FILTER comEdge._to == @u_id "
           "RETURN {name: DOCUMENT(comEdge._from).name, is_admin: comEdge.is_admin}))"
           "RETURN {user, controller, c_access, company}")
    return execute_aql_query(aql, rawResults=True, u_id=u_id, c_id=c_id)[0]


def get_model_connection_info(username, c_name, m_key):
    u_id = get_user_id(username)
    c_id = "controllers/" + c_name
    m_id = "models/" + m_key
    aql = ("LET user = DOCUMENT(@u_id) "
           "LET controller = DOCUMENT(@c_id) "
           "LET model = DOCUMENT(@m_id) "
           "LET c_access = "
           "FIRST((FOR c, cEdge IN 1..1 INBOUND @u_id controllerAccess "
           "FILTER cEdge._from == @c_id "
           "RETURN cEdge.access)) "
           "LET m_access = "
           "FIRST((FOR m, mEdge IN 1..1 INBOUND @u_id modelAccess "
           "FILTER mEdge._from == @m_id "
           "RETURN mEdge.access)) "
           "LET company = "
           "FIRST ((FOR comp, comEdge in 1..1 INBOUND @u_id companyAccess "
           "FILTER comEdge._to == @u_id "
           "RETURN {name: DOCUMENT(comEdge._from).name, is_admin: comEdge.is_admin}))"
           "RETURN {user, controller, model, c_access, m_access, company}")
    return execute_aql_query(aql, rawResults=True, u_id=u_id, c_id=c_id, m_id=m_id)[0]


def get_user_connection_info(username):
    u_id = get_user_id(username)
    aql = ("LET user = DOCUMENT(@u_id) "
           "LET company = "
           "FIRST ((FOR comp, comEdge in 1..1 INBOUND @u_id companyAccess "
           "FILTER comEdge._to == @u_id "
           "RETURN {name: comp.name, is_admin: comEdge.is_admin}))"
           "RETURN {user, company}")
    return execute_aql_query(aql, rawResults=True, u_id=u_id)[0]


def hash_username(username):
    return hashlib.md5(username.encode('utf')).hexdigest()


def get_user_id(username):
    return "users/" + hash_username(username)


def get_model_id(m_key):
    return "models/" + m_key


def get_workspace_type_id(ws_type):
    return "workspace_types/" + ws_type

###############################################################################
#                               BUNDLE FUNCTIONS                              #
###############################################################################
def create_bundle_type(name, summary, description, logo, bundle, tags):
    bundle = {"name": name,
              "summary": summary,
              "description": description,
              "logo": logo,
              "bundle": bundle,
              "tags": tags}
    aql = "INSERT @bundle INTO bundleTypes"
    execute_aql_query(aql, bundle=bundle)


def get_all_bundle_types():
    aql = "FOR b IN bundleTypes RETURN b"
    return execute_aql_query(aql, rawResults=True)

def clear_bundle_types():
    aql = "FOR b IN bundleTypes REMOVE b IN bundleTypes"
    execute_aql_query(aql, rawResults=True)
