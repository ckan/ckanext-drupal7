import logging
import uuid
import hashlib

import sqlalchemy as sa

import ckan.plugins as p
import ckan.lib.base as base
import ckan.logic as logic
import ckan.lib.helpers as h

log = logging.getLogger('ckanext.saml2')


def _no_permissions(context, msg):
    user = context['user']
    return {'success': False, 'msg': msg.format(user=user)}


@logic.auth_sysadmins_check
def user_create(context, data_dict):
    msg = p.toolkit._('Users cannot be created.')
    return _no_permissions(context, msg)


@logic.auth_sysadmins_check
def user_update(context, data_dict):
    msg = p.toolkit._('Users cannot be edited.')
    return _no_permissions(context, msg)


@logic.auth_sysadmins_check
def user_reset(context, data_dict):
    msg = p.toolkit._('Users cannot reset passwords.')
    return _no_permissions(context, msg)


@logic.auth_sysadmins_check
def request_reset(context, data_dict):
    msg = p.toolkit._('Users cannot reset passwords.')
    return _no_permissions(context, msg)


class Drupal7Plugin(p.SingletonPlugin):

    p.implements(p.IAuthenticator, inherit=True)
    p.implements(p.IRoutes, inherit=True)
    p.implements(p.IAuthFunctions, inherit=True)
    p.implements(p.IConfigurer)
    p.implements(p.IConfigurable)
    p.implements(p.ITemplateHelpers)

    drupal_session_name = None

    def get_helpers(self):
        return {'ckanext_drupal7_domain': self.get_domain}

    def get_domain(self):
        return self.domain

    def update_config(self, config):
        p.toolkit.add_template_directory(config, 'templates')

    def configure(self, config):
        self.domain = config.get('ckanext.drupal7.domain')
        self.sysadmin_role = config.get('ckanext.drupal7.sysadmin_role')
        self.connection = config.get('ckanext.drupal7.connection')

        if not (self.domain and self.sysadmin_role and self.connection):
            raise Exception('Drupal7 extension has not been configured')

    def before_map(self, map):
        map.connect(
            'drupal7_unauthorized',
            '/drupal7_unauthorized',
            controller='ckanext.drupal7.plugin:Drupal7Controller',
            action='unauthorized'
        )
        return map

    def make_password(self):
        # create a hard to guess password
        out = ''
        for n in xrange(8):
            out += str(uuid.uuid4())
        return out

    def create_drupal_session_name(self):
        server_name = self.domain or p.toolkit.request.environ['SERVER_NAME']
        session_name = 'SESS%s' % hashlib.sha256(server_name).hexdigest()[:32]
        self.drupal_session_name = session_name

    def identify(self):
        ''' This does work around saml2 authorization.
        c.user contains the saml2 id of the logged in user we need to
        convert this to represent the ckan user. '''

        # If no drupal sesssion name create one
        if self.drupal_session_name is None:
            self.create_drupal_session_name()
        # Can we find the user?
        cookies = p.toolkit.request.cookies

        drupal_sid = cookies.get(self.drupal_session_name)
        if drupal_sid:
            engine = sa.create_engine(self.connection)
            rows = engine.execute(
                'SELECT u.name, u.mail, t.uid FROM users u '
                'JOIN sessions s on s.uid=u.uid LEFT OUTER JOIN '
                '(SELECT ur.uid FROM role r JOIN users_roles ur '
                '     ON r.rid = ur.rid WHERE r.name=%s '
                ') AS t ON t.uid = u.uid '
                'WHERE s.sid=%s',
                [self.sysadmin_role, str(drupal_sid)])

            for row in rows:
                self.user(row)
                break

    def user(self, user_data):
        try:
            user = p.toolkit.get_action('user_show')({'return_minimal': True, 'keep_sensitive_data': True}, {'id': user_data.name})
        except p.toolkit.ObjectNotFound:
            pass
            user = None
        if user:
            # update the user in ckan if not matching drupal data
            if (user_data.mail != user['email']
                    or bool(user_data.uid) != user['sysadmin']):
                user['email'] = user_data.mail
                user['sysadmin'] = bool(user_data.uid)
                user['id'] = user_data.name
                user = p.toolkit.get_action('user_update')({'ignore_auth': True}, user)
        else:
            user = {'email': user_data.mail,
                    'name': user_data.name,
                    'password': self.make_password(),
                    'sysadmin': bool(user_data.uid),}
            user = p.toolkit.get_action('user_create')({'ignore_auth': True}, user)
            p.toolkit.c.user = user['name']

    def abort(self, status_code, detail, headers, comment):
        # HTTP Status 401 causes a login redirect.  We need to prevent this
        # unless we are actually trying to login.
        if (status_code == 401
            and p.toolkit.request.environ['PATH_INFO'] != '/user/login'):
                h.redirect_to('drupal7_unauthorized')
        return (status_code, detail, headers, comment)

    def get_auth_functions(self):
        # we need to prevent some actions being authorized.
        return {
            'user_create': user_create,
            'user_update': user_update,
            'user_reset': user_reset,
            'request_reset': request_reset,
        }


class Drupal7Controller(base.BaseController):

    def unauthorized(self):
        # This is our you are not authorized page
        c = p.toolkit.c
        c.code = 401
        c.content = p.toolkit._('You are not authorized to do this')
        return p.toolkit.render('error_document_template.html')
