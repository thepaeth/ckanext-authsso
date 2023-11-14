import ckan.plugins as plugins, logging
import ckan.plugins.toolkit as toolkit
from flask import make_response
from blueprint import route_auth
log = logging.getLogger(__name__)


class AuthssoPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    # plugins.implements(plugins.IAuthenticator)
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
    # IAuthenticator
    # def identify(self):
    #     if toolkit.request.path not in [toolkit.url_for('authsso.login')]:
    #         response = make_response(toolkit.request.path)
    #     else:
    #         toolkit.g.user = 'ckan_admin'
    #         # return response
    # def logout(self):
    #     toolkit.g.user = None

    #     return toolkit.redirect_to('home.index')
            
    
