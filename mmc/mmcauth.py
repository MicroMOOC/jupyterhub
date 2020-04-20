# -*- coding: utf-8 -*-

import uuid
import json
import requests

from traitlets import Bool
from tornado import gen
from tornado import web
from requests import ConnectionError

from jupyterhub.auth import Authenticator
from jupyterhub.handlers import BaseHandler
from jupyterhub.utils import url_path_join


class MMCAuthenticateHandler(BaseHandler):
    """
    Handler for /mmclogin

    Creates a new user with a user id, and auto starts their server
    """
    def initialize(self, force_new_server, process_user):
        super().initialize()

    @gen.coroutine
    def get(self):
        raw_user = yield self.get_current_user()
        if not raw_user:
            bearer = self.get_argument('bearer', '')
            if not bearer:
                raise web.HTTPError(400, "token is missing")
            
            userInfo = self.getUserInfoByToken(bearer)
            if not userInfo or not userInfo['userId']:
                raise web.HTTPError(401, "invalid token")

            raw_user = self.user_from_username(userInfo['userId'])
            self.set_login_cookie(raw_user)
        user = yield gen.maybe_future(raw_user)
        self.redirect(self.get_next_url(user))

    def getUserInfoByToken(self, token):
        REQUEST_URL_DEV = "https://newton-dev-samwell.micromooc.com/samwell/api/v1/user/current?bearer=" + token
        REQUEST_URL_PROD = "https://newton-prod-samwell.micromooc.com/samwell/api/v1/user/current?bearer=" + token

        try:
            rsp = requests.get(REQUEST_URL_DEV, verify=False)
            jsonResp = json.loads(rsp.text)
            return jsonResp['data']
        except ConnectionError:
            raise web.HTTPError(500, "newton user service connect fail")

class MMCAuthenticator(Authenticator):
    """
    JupyterHub Authenticator for use with tmpnb.org

    When JupyterHub is configured to use this authenticator, visiting the home
    page immediately logs the user in with a randomly generated UUID if they
    are already not logged in, and spawns a server for them.
    """

    auto_login = True
    login_service = 'MMCLogin'

    def get_handlers(self, app):
        return [
            ('/mmclogin', MMCAuthenticateHandler)
        ]

    def login_url(self, base_url):
        return url_path_join(base_url, 'mmclogin')