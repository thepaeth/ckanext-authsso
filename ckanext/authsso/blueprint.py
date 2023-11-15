# encoding: utf-8
from flask import Blueprint, make_response, request
from ckan import plugins as p
import logging, requests, json, string, secrets, os
import ckan.model as model
import ckan.logic as logic
import ckan.lib.dictization.model_dictize as model_dictize
from ckan.lib import base
from ckan.lib.jobs import DEFAULT_QUEUE_NAME
from ckan.views.user import set_repoze_user
from ckan.common import config, g

log = logging.getLogger(__name__)
toolkit = p.toolkit

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
  # token = params['token']
  headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer {}'.format(token)
  }
  try:
    with requests.Session() as s:
      s.verify = False
      res = s.post(url='{}{}'.format(authen_url, userinfo_path), headers=headers)
  except requests.exceptions.RequestException as e:
    return None
  return res.json()

def get_ckan_user(email):
  ckan_users = model.User.by_email(email)
  if len(ckan_users) > 0:
    ckan_user = ckan_users[0]
    return ckan_user

def create_user(context, username, email, full_name, org=None):
  data_dict ={
    'name': username,
    'fullname': full_name,
    'email': email,
    'password': generate_password()
  }

  try:
    user_dict = logic.get_action('user_create')(context, data_dict)
  except logic.ValidationError as e:
    error_message = (e.error_summary or e.message or r.error_dict)
    log.error(error_message)
    base.abort(400, error_message)

  return user_dict

def login():
  if not g.user:
    return toolkit.redirect_to('{}'.format(authen_page))
  return toolkit.redirect_to('home.index')

def auth():
  token = request.args.get(token_params)
  args = {'token': token}
  context = {
      u'ignore_auth': True,
      u'keep_email': True,
      u'model': model
  }
  userinfo = get_user_info(token)
  email = userinfo['internet_address']['email']['value']
  # if user:
  #   userinfo = userinfo['user_info']
  #   user_email = userinfo['email']
  user = get_ckan_user(email)
  username = userinfo['uuid']
  fullname = '{} {}'.format(userinfo['name_th']['first_name']['value'], userinfo['name_th']['last_name']['value'])

  if not user:
    user_dict = create_user(context, username, email, fullname)
  else:
    user_dict = model_dictize.user_dictize(user, context)
  
  log.info(user_dict)
  g.user = user_dict['name']
  g.userobj = model.User.by_name(g.user)
  relay_state = request.form.get('RelayState')
  redirect_target = toolkit.url_for(
    str(relay_state), _external=True
  ) if relay_state else 'user.me'
  resp = toolkit.redirect_to(redirect_target)
  set_repoze_user(g.user, resp)

  return resp
  # return request.param.get('token')

route_auth.add_url_rule('/user/login', view_func=login)
route_auth.add_url_rule('/auth', view_func=auth)