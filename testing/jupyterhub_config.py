"""sample jupyterhub config file for testing

configures jupyterhub with dummyauthenticator and simplespawner
to enable testing without administrative privileges.
"""

c = get_config()  # noqa

from jupyterhub.auth import DummyAuthenticator
from jupyterhub.mmcauth import MMCAuthenticator, MMCAuthenticateHandler

# c.JupyterHub.authenticator_class = DummyAuthenticator
c.JupyterHub.authenticator_class = MMCAuthenticator

# Optionally set a global password that all users must use
# c.DummyAuthenticator.password = "your_password"

from jupyterhub.spawner import SimpleLocalProcessSpawner

c.JupyterHub.spawner_class = SimpleLocalProcessSpawner

c.MMCAuthenticator.mmc_userinfo_url = 'https://newton-dev-samwell.micromooc.com/samwell/api/v1/user/current'
