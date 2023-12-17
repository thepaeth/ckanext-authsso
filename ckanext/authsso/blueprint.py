# encoding: utf-8
from flask import Blueprint, make_response, request
from ckan import plugins as p
import logging, requests, json, string, secrets, os, sqlalchemy as sa
import ckan.model as model
import ckan.logic as logic, ckan.lib.helpers as h
import ckan.lib.dictization.model_dictize as model_dictize
from ckan.lib import base
from ckan.lib.jobs import DEFAULT_QUEUE_NAME
from ckan.views.user import set_repoze_user, me, _get_repoze_handler, logged_in
from ckan.views.dashboard import index
from ckan.common import config, g, c, request, _

log = logging.getLogger(__name__)
toolkit = p.toolkit
render = base.render

queue = DEFAULT_QUEUE_NAME
route_auth = Blueprint('authsso', __name__)
authen_url = os.environ.get('CKAN___AUTHSSO__AUTHEN_HOST', config.get('authsso.authen_host'))
userinfo_path = os.environ.get('CKAN___AUTHSSO__AUTHEN_PATH', config.get('authsso.authen_path'))
authen_page = os.environ.get('CKAN___AUTHSSO__AUTHEN_PAGE', config.get('authsso.authen_page'))
token_params = os.environ.get('CKAN___AUTHSSO__TOKEN_PARAMS', config.get('authsso.token_params'))

def generate_password():
    alphabet = string.ascii_letters + string.digits
    password = ''.join(secrets.choice(alphabet) for i in range(8))
    return password

def get_user_info(token):
  headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer {}'.format(token)
  }
  try:
    with requests.Session() as s:
      s.verify = False
      res = s.get(url='{}{}'.format(authen_url, userinfo_path), headers=headers)
  except requests.exceptions.RequestException as e:
    return None
  return res.json()

def get_ckan_user(email):
  ckan_users = model.User.by_email(email)
  if len(ckan_users) > 0:
    ckan_user = ckan_users[0]
    return ckan_user

def get_ckan_user_with_uuid(uuid):
  ckan_users = model.Session.query(model.User).filter(
      model.User.plugin_extras[('uuid',)].cast(sa.Text()) == uuid
    ).all()
  model.Session.remove()
  if len(ckan_users) > 0:
    ckan_user = ckan_users[0]
    return ckan_user

def get_userid(userinfo):
  return userinfo['uuid']

def get_citizen_id(userinfo):
  return userinfo['person_id']['citizen_id']['value']

def gen_username(citizen_id):
  return 'dip-{}{}'.format(citizen_id[1:3], citizen_id[5:])

def user_extra(uuid):
  return {
    'uuid': uuid,
    'type': 'dip-eservice'
  }

def create_user(context, userinfo, email, full_name, org=None):
  ctz = get_citizen_id(userinfo)
  username = gen_username(ctz)
  uuid = get_userid(userinfo)
  data_dict = {
    'name': username,
    'fullname': full_name,
    'email': email,
    'password': ctz,
    'plugin_extras': user_extra(uuid)
  }

  try:
    user_dict = logic.get_action('user_create')(context, data_dict)
  except logic.ValidationError as e:
    error_message = (e.error_summary or e.message or r.error_dict)
    log.error(error_message)
    base.abort(400, error_message)
  
  return user_dict


def login():
  for item in p.PluginImplementations(p.IAuthenticator):
    response = item.login()
    if response:
      return response

  extra_vars = {}
  if g.user:
    return render(u'user/logout_first.html', extra_vars)

  came_from = request.params.get(u'came_from')
  if not came_from:
    came_from = h.url_for(u'user.logged_in')
  g.login_handler = h.url_for(
    _get_repoze_handler(u'login_handler_path'), came_from=came_from)
  g.authen_page_url = authen_page
  return render('user/login.html', extra_vars)

def auth():
  token = request.args.get(token_params)
  args = {'token': token}
  context = {
      u'ignore_auth': True,
      u'keep_email': True,
      u'model': model,
      u'session': model.Session
  }
  userinfo = get_user_info(token)
  email = userinfo['internet_address']['email']['value']
  if not email:
    email = '{}@mail.tmp'.format(userinfo['uuid'])
  user = get_ckan_user(email)
  username = userinfo['uuid']
  fullname = '{} {}'.format(userinfo['name_th']['first_name']['value'], userinfo['name_th']['last_name']['value'])
  
  if not user:
    user = get_ckan_user_with_uuid(get_userid(userinfo))
    if not user:
      user_dict = create_user(context, userinfo, email, fullname)
    else:
      user_dict = model_dictize.user_dictize(user, context)
  else:
    user_dict = model_dictize.user_dictize(user, context)
    if user.plugin_extras is None:
      user.name = gen_username(get_citizen_id(userinfo))
      user.password = get_citizen_id(userinfo)
      user.plugin_extras = user_extra(get_userid(userinfo))
      user.save()

  g.user = user_dict['name']
  g.userobj = model.User.by_name(g.user)
  relay_state = request.form.get('RelayState')

  resp = h.redirect_to(u'user.me')
  set_repoze_user(user_dict['name'], resp)

  return resp

route_auth.add_url_rule('/user/login', view_func=login)
route_auth.add_url_rule('/auth', view_func=auth)