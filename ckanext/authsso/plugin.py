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
            
    
