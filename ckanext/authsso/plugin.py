import ckan.plugins as plugins, logging
import ckan.plugins.toolkit as toolkit
from flask import make_response
from ckan.common import g

from blueprint import route_auth
log = logging.getLogger(__name__)


class AuthssoPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    # plugins.implements(plugins.IAuthenticator, inherit=True)
    plugins.implements(plugins.IBlueprint)

    # IConfigurer

    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')
        toolkit.add_public_directory(config_, 'public')
        toolkit.add_resource('fanstatic',
            'authsso')
        config_['authsso.authen_host']  = config_.get('authsso.authen_host', 'http://172.16.99.1:8000')
        config_['authsso.authen_path']  = config_.get('authsso.authen_path', '/user/getinfo')
        config_['authsso.authen_page']  = config_.get('authsso.authen_page', 'http://172.16.99.1:8000/login/')
        config_['authsso.token_params'] = config_.get('authsso.token_params', 'token')

    # IBlueprint
    def get_blueprint(self):
        return [route_auth]

    # def identity(self):
    #     pass
    #     log.info(toolkit.requqest.path)
    #     if toolkit.request.path == toolkit.url_for('authsso.auth'):
    #         token = request.args.get(token_params)
    #         args = {'token': token}
    #         log.info(request.environ)
    #         context = {
    #             u'ignore_auth': True,
    #             u'keep_email': True,
    #             u'model': model,
    #             u'session': model.Session
    #         }
    #         userinfo = get_user_info(token)
    #         email = userinfo['internet_address']['email']['value']
    #         if not email:
    #             email = '{}@mail.tmp'.format(userinfo['uuid'])
    #         user = get_ckan_user(email)
    #         username = userinfo['uuid']
    #         fullname = '{} {}'.format(userinfo['name_th']['first_name']['value'], userinfo['name_th']['last_name']['value'])

    #         if not user:
    #             user_dict = create_user(context, username, email, fullname)
    #         else:
    #             user_dict = model_dictize.user_dictize(user, context)
            
    #         g.user = user_dict['name']
    #         g.userobj = model.User.by_name(g.user)
    #         relay_state = request.form.get('RelayState')
    #         redirect_target = toolkit.url_for(
    #             str(relay_state), _external=True) if relay_state else u'user.me'
    #         resp = toolkit.redirect_to(redirect_target)
    #         set_repoze_user(g.user, resp)

    #         return resp
    
    # def login(self):
    #     return toolkit.redirect_to('authsso.login')
            
    
