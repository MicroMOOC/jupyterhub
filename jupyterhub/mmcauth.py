# -*- coding: utf-8 -*-

import uuid
import json
import os
import requests

from urllib import parse
from traitlets import Unicode, Bool
from tornado import gen
from tornado import web
from requests import ConnectionError
from tornado.httputil import url_concat

from .auth import Authenticator
from .handlers import BaseHandler
from .utils import url_path_join


class MMCAuthenticateHandler(BaseHandler):
    """
    Handler for /mmclogin

    Creates a new user with a user id, and auto starts their server
    """

    def initialize(self, mmc_userinfo_url):
        super().initialize()
        self.mmc_userinfo_url = mmc_userinfo_url

    @gen.coroutine
    def get(self):
        raw_user = yield self.get_current_user()
        if not raw_user:
            # 认证token
            bearer = self.get_argument('bearer', '')
            # 应用，notebook 或 lab
            app = self.get_argument('app', '')
            if not bearer:
                nextUrl= self.get_argument('next', '')
                if not nextUrl:
                    raise web.HTTPError(400, "token is missing")
                else:
                    # get token from next param
                    nextUrl = parse.unquote(nextUrl)
                    parsed = parse.urlparse(nextUrl)
                    querys = parse.parse_qs(parsed.query)
                    bearerParams= querys.get('bearer')
                    if not bearerParams:
                        raise web.HTTPError(400, "token is missing")
                    else:
                        bearer = bearerParams[0]
                        appParams = querys.get('app')
                        if not appParams:
                            app = appParams[0]

            userInfo = self.getUserInfoByToken(bearer)
            if not userInfo or not userInfo['userId']:
                raise web.HTTPError(401, "invalid token")

            # 用户ID      
            userId = userInfo['userId']
            if app == 'lab':
                userId = userId + '-' + app

            raw_user = self.user_from_username(userId)
            self.set_login_cookie(raw_user)
        user = yield gen.maybe_future(raw_user)
        self.redirect(self.get_next_url(user))

    def getUserInfoByToken(self, token):
        request_url = url_concat(
            self.mmc_userinfo_url,
            {'bearer': token}
        )
        try:
            rsp = requests.get(request_url, verify=False)
            jsonResp = json.loads(rsp.text)
            if 'success' in jsonResp and jsonResp['success'] == False:
                raise web.HTTPError(500, "newton user service connect fail")
            elif 'success' in jsonResp and jsonResp['success'] == True:
                if jsonResp['data']:
                    return jsonResp['data']
                else:
                    return None
        except ConnectionError:
            raise web.HTTPError(401, "newton user not found")

class MMCAuthenticator(Authenticator):
    """
    JupyterHub Authenticator for use with tmpnb.org

    When JupyterHub is configured to use this authenticator, visiting the home
    page immediately logs the user in with a randomly generated UUID if they
    are already not logged in, and spawns a server for them.
    """

    auto_login = True
    login_service = 'MMCLogin'

    mmc_userinfo_url = Unicode(
        os.getenv('MMC_USERINFO_URL', ''),
        config=True,
        help="""""",
    )

    def get_handlers(self, app):
        extra_settings = {
          'mmc_userinfo_url': self.mmc_userinfo_url
        }
        return [
            ('/mmclogin', MMCAuthenticateHandler, extra_settings),
        ]

    def login_url(self, base_url):
        return url_path_join(base_url, 'mmclogin')