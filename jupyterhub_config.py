# Configuration file for jupyterhub.

#------------------------------------------------------------------------------
# Application(SingletonConfigurable) configuration
#------------------------------------------------------------------------------

## This is an application.

## The date format used by logging formatters for %(asctime)s
#c.Application.log_datefmt = '%Y-%m-%d %H:%M:%S'

## The Logging format template
#c.Application.log_format = '[%(name)s]%(highlevel)s %(message)s'

## Set the log level by value or name.
#c.Application.log_level = 30

#------------------------------------------------------------------------------
# JupyterHub(Application) configuration
#------------------------------------------------------------------------------

## An Application for starting a Multi-User Jupyter Notebook server.

## Maximum number of concurrent servers that can be active at a time.
#  
#  Setting this can limit the total resources your users can consume.
#  
#  An active server is any server that's not fully stopped. It is considered
#  active from the time it has been requested until the time that it has
#  completely stopped.
#  
#  If this many user servers are active, users will not be able to launch new
#  servers until a server is shutdown. Spawn requests will be rejected with a 429
#  error asking them to try again.
#  
#  If set to 0, no limit is enforced.
#c.JupyterHub.active_server_limit = 0

## Duration (in seconds) to determine the number of active users.
#c.JupyterHub.active_user_window = 1800

## Resolution (in seconds) for updating activity
#  
#  If activity is registered that is less than activity_resolution seconds more
#  recent than the current value, the new value will be ignored.
#  
#  This avoids too many writes to the Hub database.
#c.JupyterHub.activity_resolution = 30

## Grant admin users permission to access single-user servers.
#  
#  Users should be properly informed if this is enabled.
#c.JupyterHub.admin_access = False

## DEPRECATED since version 0.7.2, use Authenticator.admin_users instead.
#c.JupyterHub.admin_users = set()

## Allow named single-user servers per user
c.JupyterHub.allow_named_servers = False

## Answer yes to any questions (e.g. confirm overwrite)
#c.JupyterHub.answer_yes = False

## PENDING DEPRECATION: consider using services
#  
#  Dict of token:username to be loaded into the database.
#  
#  Allows ahead-of-time generation of API tokens for use by externally managed
#  services, which authenticate as JupyterHub users.
#  
#  Consider using services for general services that talk to the JupyterHub API.
c.JupyterHub.api_tokens = {
    '56afdeec4c3440cda6e29870791787e6': 'glovas'
}

## Authentication for prometheus metrics
#c.JupyterHub.authenticate_prometheus = True

## Class for authenticating users.
#  
#          This should be a subclass of :class:`jupyterhub.auth.Authenticator`
#  
#          with an :meth:`authenticate` method that:
#  
#          - is a coroutine (asyncio or tornado)
#          - returns username on success, None on failure
#          - takes two arguments: (handler, data),
#            where `handler` is the calling web.RequestHandler,
#            and `data` is the POST form data from the login page.
#  
#          .. versionchanged:: 1.0
#              authenticators may be registered via entry points,
#              e.g. `c.JupyterHub.authenticator_class = 'pam'`
#  
#  Currently installed: 
#    - default: jupyterhub.auth.PAMAuthenticator
#    - dummy: jupyterhub.auth.DummyAuthenticator
#    - pam: jupyterhub.auth.PAMAuthenticator
#    - auth0: oauthenticator.auth0.Auth0OAuthenticator
#    - awscognito: oauthenticator.awscognito.AWSCognitoAuthenticator
#    - azuread: oauthenticator.azuread.AzureAdOAuthenticator
#    - bitbucket: oauthenticator.bitbucket.BitbucketOAuthenticator
#    - cilogon: oauthenticator.cilogon.CILogonOAuthenticator
#    - generic-oauth: oauthenticator.generic.GenericOAuthenticator
#    - github: oauthenticator.github.GitHubOAuthenticator
#    - gitlab: oauthenticator.gitlab.GitLabOAuthenticator
#    - globus: oauthenticator.globus.GlobusOAuthenticator
#    - google: oauthenticator.google.GoogleOAuthenticator
#    - local-auth0: oauthenticator.auth0.LocalAuth0OAuthenticator
#    - local-awscognito: oauthenticator.awscognito.LocalAWSCognitoAuthenticator
#    - local-azuread: oauthenticator.azuread.LocalAzureAdOAuthenticator
#    - local-bitbucket: oauthenticator.bitbucket.LocalBitbucketOAuthenticator
#    - local-cilogon: oauthenticator.cilogon.LocalCILogonOAuthenticator
#    - local-generic-oauth: oauthenticator.generic.LocalGenericOAuthenticator
#    - local-github: oauthenticator.github.LocalGitHubOAuthenticator
#    - local-gitlab: oauthenticator.gitlab.LocalGitLabOAuthenticator
#    - local-globus: oauthenticator.globus.LocalGlobusOAuthenticator
#    - local-google: oauthenticator.google.LocalGoogleOAuthenticator
#    - local-mediawiki: oauthenticator.mediawiki.LocalMWOAuthenticator
#    - local-okpy: oauthenticator.okpy.LocalOkpyOAuthenticator
#    - local-openshift: oauthenticator.openshift.LocalOpenShiftOAuthenticator
#    - mediawiki: oauthenticator.mediawiki.MWOAuthenticator
#    - okpy: oauthenticator.okpy.OkpyOAuthenticator
#    - openshift: oauthenticator.openshift.OpenShiftOAuthenticator
#c.JupyterHub.authenticator_class = 'jupyterhub.auth.PAMAuthenticator'


## AdyneLogoutHandler Customization
#
#  This subclass of LogoutHandler renders idle timeout page when session is logged out 
#  due to inactivity.

import asyncio
from tornado import web
from jupyterhub.utils import maybe_future
from jupyterhub.handlers.base import BaseHandler
from jupyterhub.handlers.login import LoginHandler
from jupyterhub.handlers.login import LogoutHandler
from urllib.parse import urlparse

class IdleLogoutHandler(LogoutHandler):

    async def get(self):
        await self.default_handle_logout()
        await self.handle_logout()
        await self.render_idle_logout_page()

    async def render_idle_logout_page(self):
        if self.authenticator.auto_login:
            html = self.render_template('logout-idle.html')
            self.finish(html)
        else:
            self.redirect(self.settings['login_url'], permanent=False)

## AdyneLoginHandler Customization
#
#  This subclass of LoginHandler manages auto login when jupyterhub web addresses 
#  include embedded prod id's.  These are typically for jupyter notebooks with the 
#  appmode enabled, so have no code exposed and run in the browser as an application
#
#  For now to maintain active kerberos tokens, the prod id is authenticaed by reading 
#  the passwrd from a secure location on the machine.  if permanent kerberos tickets 
#  are established, then the authentication step can be skipped, by setting 
#     
#      authenticate_prod_id = False
#
#  If a user's browser is currently logged in, it will assume the id of the cuurent user
#  To disable auto login completely, set
# 
#     c.Authenticator.auto_login = False
class AdyneLoginHandler(LoginHandler):

    async def get(self):
        self.statsd.incr('login.request')
        user = self.current_user
        if user:
            # set new login cookie
            # because single-user cookie may have been cleared or incorrect
            self.set_login_cookie(user)
            self.redirect(self.get_next_url(user), permanent=False)
        else:
            uri = self.request.uri
            if self.authenticator.auto_login and uri != '/hub/login':
                try:
                    u0 = urlparse(uri)
                    u1 = u0.query.split('%2F')
                    u2 = [x for sublist in [x.split('%252F') for x in u1] for x in sublist]
                    user = u2[u2.index('user')+1]
                except Exception as ex:
                    user = ''
                    self.log.warn('Exception parsing url: %s' % url)
                auto_login_url = self.authenticator.login_url(self.hub.base_url)
                if auto_login_url == self.settings['login_url']:
                    # auto_login without a custom login handler
                    # means that auth info is already in the request
                    # (e.g. REMOTE_USER header)
                    username = user 
                    if username.startswith('jhub'):
                        data = {'username': username}
                        user = await self.login_user(data=data)
                        if user is None:
                            # auto_login failed, just 403
                            raise web.HTTPError(403)
                        else:
                            self.redirect(self.get_next_url(user))
                    else:
                        self.finish(self._render(username=''))
                else:
                    if self.get_argument('next', default=False):
                        auto_login_url = url_concat(
                            auto_login_url, {'next': self.get_next_url()}
                        )
                    self.redirect(auto_login_url)
                return
            username = self.get_argument('username', default='')
            self.finish(self._render(username=username))


from tornado.httputil import url_concat
from jupyterhub.utils import url_path_join
from jupyterhub.handlers.base import UserUrlHandler

class AutoUserUrlHandler(UserUrlHandler):
    @web.authenticated
    async def get(self, user_name, user_path):
        user = self.current_user
        self.log.info('************ AutoUserUrlHandler: current user: %s    login user: %s   path: %s' % (user, user_name, user_path))
        if user_name.startswith('jhub') and user.name == user_name:
            server_name = ''
            spawner = user.spawners[server_name]
            if not spawner.ready:
                spawn_url = url_concat(
                   url_path_join(self.hub.base_url, "spawn", user.escaped_name, server_name),{"next": self.request.uri},
                )
                self.redirect(spawn_url)
            else:
                await self._redirect_to_user_server(user, spawner)
        else:
            await super(AutoUserUrlHandler, self).get(user_name, user_path)

import pamela
from jupyterhub.auth import PAMAuthenticator
from tornado import gen

class KerberosPAMAuthenticator(PAMAuthenticator):
    def __init__(self, **kwargs):
        # app_log.info('authenticator constructor')        
        super(KerberosPAMAuthenticator, self).__init__(**kwargs)

    # controls whether to authenticate prod id...
    authenticate_prod_id = True
    
    @gen.coroutine
    def authenticate(self, handler, data):
        """
        Authenticate with PAM, and return the username if login is successful.
        Establish credentials when authenticating instead of reinitializing them
        so that a Kerberos cred cache has the proper UID in it.
        """
        username = data['username'].lower()
        # for prod id look up password and authenticate 
        if self.auto_login and username.startswith('jhub'):
            try:
                if self.authenticate_prod_id:
                    with open('/root/jhub/%s' % username, 'r') as f:
                        data['password'] = f.readline().replace('\n','')
                else:
                    return {'name': username}
            except Exception as ex:
               self.log.exception('Error reading password file for %s\n%r' % (username, ex))
        try:
            pamela.authenticate(username, data['password'], service=self.service, resetcred=pamela.PAM_ESTABLISH_CRED)
        except pamela.PAMError as e:
            if handler is not None:
                self.log.warning("PAM Authentication failed (%s@%s): %s", username, handler.request.remote_ip, e)
            else:
                self.log.warning("PAM Authentication failed: %s", e)
        else:
            return {'name': username, 'auth_state': {'KERBEROS_PASSWORD': data['password']}}

    @gen.coroutine
    def pre_spawn_start(self, user, spawner):
        """Pass upstream_token to spawner via environment variable"""
        auth_state = yield user.get_auth_state()
        if not auth_state:
            # auth_state not enabled
            return
        spawner.environment['KERBEROS_PASSWORD'] = auth_state['KERBEROS_PASSWORD']

    # redirect to use login handler customized for auto login
    def get_handlers(self, app):
        handlers = [(r'/logout/idle', IdleLogoutHandler)]
        if app.authenticator.auto_login:
            handlers.extend([(r'/login', AdyneLoginHandler), (r'/user/(?P<user_name>[^/]+)(?P<user_path>/.*)?', AutoUserUrlHandler)])
        else:
            handlers.extend(super(KerberosPAMAuthenticator, self).get_handlers(app))
        return handlers

c.JupyterHub.authenticator_class = KerberosPAMAuthenticator

## The base URL of the entire application.
#  
#  Add this to the beginning of all JupyterHub URLs. Use base_url to run
#  JupyterHub within an existing website.
#  
#  .. deprecated: 0.9
#      Us JupyterHub.bind_url
#c.JupyterHub.base_url = '/'

## The public facing URL of the whole JupyterHub application.
#  
#  This is the address on which the proxy will bind. Sets protocol, ip, base_url
#c.JupyterHub.bind_url = 'http://:8000'

## Whether to shutdown the proxy when the Hub shuts down.
#  
#  Disable if you want to be able to teardown the Hub while leaving the proxy
#  running.
#  
#  Only valid if the proxy was starting by the Hub process.
#  
#  If both this and cleanup_servers are False, sending SIGINT to the Hub will
#  only shutdown the Hub, leaving everything else running.
#  
#  The Hub should be able to resume from database state.
c.JupyterHub.cleanup_proxy = False

## Whether to shutdown single-user servers when the Hub shuts down.
#  
#  Disable if you want to be able to teardown the Hub while leaving the single-
#  user servers running.
#  
#  If both this and cleanup_proxy are False, sending SIGINT to the Hub will only
#  shutdown the Hub, leaving everything else running.
#  
#  The Hub should be able to resume from database state.
c.JupyterHub.cleanup_servers = False

## Maximum number of concurrent users that can be spawning at a time.
#  
#  Spawning lots of servers at the same time can cause performance problems for
#  the Hub or the underlying spawning system. Set this limit to prevent bursts of
#  logins from attempting to spawn too many servers at the same time.
#  
#  This does not limit the number of total running servers. See
#  active_server_limit for that.
#  
#  If more than this many users attempt to spawn at a time, their requests will
#  be rejected with a 429 error asking them to try again. Users will have to wait
#  for some of the spawning services to finish starting before they can start
#  their own.
#  
#  If set to 0, no limit is enforced.
#c.JupyterHub.concurrent_spawn_limit = 100

## The config file to load
#c.JupyterHub.config_file = 'jupyterhub_config.py'

## DEPRECATED: does nothing
#c.JupyterHub.confirm_no_ssl = False

## Number of days for a login cookie to be valid. Default is two weeks.
#c.JupyterHub.cookie_max_age_days = 14

## The cookie secret to use to encrypt cookies.
#  
#  Loaded from the JPY_COOKIE_SECRET env variable by default.
#  
#  Should be exactly 256 bits (32 bytes).
#c.JupyterHub.cookie_secret = b''

## File in which to store the cookie secret.
c.JupyterHub.cookie_secret_file = '/srv/jupyterhub/jupyterhub_cookie_secret'

## The location of jupyterhub data files (e.g. /usr/local/share/jupyterhub)
#c.JupyterHub.data_files_path = '/opt/tljh/hub/share/jupyterhub'

## Include any kwargs to pass to the database connection. See
#  sqlalchemy.create_engine for details.
#c.JupyterHub.db_kwargs = {}

## url for the database. e.g. `sqlite:///jupyterhub.sqlite`
#c.JupyterHub.db_url = 'sqlite:///jupyterhub.sqlite'

## log all database transactions. This has A LOT of output
#c.JupyterHub.debug_db = False

## DEPRECATED since version 0.8: Use ConfigurableHTTPProxy.debug
#c.JupyterHub.debug_proxy = False

## If named servers are enabled, default name of server to spawn or open, e.g. by
#  user-redirect.
#c.JupyterHub.default_server_name = ''

## The default URL for users when they arrive (e.g. when user directs to "/")
#  
#  By default, redirects users to their own server.
#c.JupyterHub.default_url = '/lab'

## Dict authority:dict(files). Specify the key, cert, and/or ca file for an
#  authority. This is useful for externally managed proxies that wish to use
#  internal_ssl.
#  
#  The files dict has this format (you must specify at least a cert)::
#  
#      {
#          'key': '/path/to/key.key',
#          'cert': '/path/to/cert.crt',
#          'ca': '/path/to/ca.crt'
#      }
#  
#  The authorities you can override: 'hub-ca', 'notebooks-ca', 'proxy-api-ca',
#  'proxy-client-ca', and 'services-ca'.
#  
#  Use with internal_ssl
#c.JupyterHub.external_ssl_authorities = {}

## Register extra tornado Handlers for jupyterhub.
#  
#  Should be of the form ``("<regex>", Handler)``
#  
#  The Hub prefix will be added, so `/my-page` will be served at `/hub/my-page`.
c.JupyterHub.extra_handlers = [(r'/login', AdyneLoginHandler)]

## DEPRECATED: use output redirection instead, e.g.
#  
#  jupyterhub &>> /var/log/jupyterhub.log
#c.JupyterHub.extra_log_file = ''

## Extra log handlers to set on JupyterHub logger
#c.JupyterHub.extra_log_handlers = []

## Generate certs used for internal ssl
#c.JupyterHub.generate_certs = False

## Generate default config file
#c.JupyterHub.generate_config = False

## The URL on which the Hub will listen. This is a private URL for internal
#  communication. Typically set in combination with hub_connect_url. If a unix
#  socket, hub_connect_url **must** also be set.
#  
#  For example:
#  
#      "http://127.0.0.1:8081"
#      "unix+http://%2Fsrv%2Fjupyterhub%2Fjupyterhub.sock"
#  
#  .. versionadded:: 0.9
#c.JupyterHub.hub_bind_url = 'http://127.0.0.1:8081'

## The ip or hostname for proxies and spawners to use for connecting to the Hub.
#  
#  Use when the bind address (`hub_ip`) is 0.0.0.0 or otherwise different from
#  the connect address.
#  
#  Default: when `hub_ip` is 0.0.0.0, use `socket.gethostname()`, otherwise use
#  `hub_ip`.
#  
#  Note: Some spawners or proxy implementations might not support hostnames.
#  Check your spawner or proxy documentation to see if they have extra
#  requirements.
#  
#  .. versionadded:: 0.8
#c.JupyterHub.hub_connect_ip = ''

## DEPRECATED
#  
#  Use hub_connect_url
#  
#  .. versionadded:: 0.8
#  
#  .. deprecated:: 0.9
#      Use hub_connect_url
#c.JupyterHub.hub_connect_port = 0

## The URL for connecting to the Hub. Spawners, services, and the proxy will use
#  this URL to talk to the Hub.
#  
#  Only needs to be specified if the default hub URL is not connectable (e.g.
#  using a unix+http:// bind url).
#  
#  .. seealso::
#      JupyterHub.hub_connect_ip
#      JupyterHub.hub_bind_url
#  
#  .. versionadded:: 0.9
#c.JupyterHub.hub_connect_url = ''

## The ip address for the Hub process to *bind* to.
#  
#  By default, the hub listens on localhost only. This address must be accessible
#  from the proxy and user servers. You may need to set this to a public ip or ''
#  for all interfaces if the proxy or user servers are in containers or on a
#  different host.
#  
#  See `hub_connect_ip` for cases where the bind and connect address should
#  differ, or `hub_bind_url` for setting the full bind URL.
#c.JupyterHub.hub_ip = '127.0.0.1'

## The internal port for the Hub process.
#  
#  This is the internal port of the hub itself. It should never be accessed
#  directly. See JupyterHub.port for the public port to use when accessing
#  jupyterhub. It is rare that this port should be set except in cases of port
#  conflict.
#  
#  See also `hub_ip` for the ip and `hub_bind_url` for setting the full bind URL.
#c.JupyterHub.hub_port = 8081

## Timeout (in seconds) to wait for spawners to initialize
#  
#  Checking if spawners are healthy can take a long time if many spawners are
#  active at hub start time.
#  
#  If it takes longer than this timeout to check, init_spawner will be left to
#  complete in the background and the http server is allowed to start.
#  
#  A timeout of -1 means wait forever, which can mean a slow startup of the Hub
#  but ensures that the Hub is fully consistent by the time it starts responding
#  to requests. This matches the behavior of jupyterhub 1.0.
#  
#  .. versionadded: 1.1.0
c.JupyterHub.init_spawners_timeout = 30

## The location to store certificates automatically created by JupyterHub.
#  
#  Use with internal_ssl
#c.JupyterHub.internal_certs_location = 'internal-ssl'

## Enable SSL for all internal communication
#  
#  This enables end-to-end encryption between all JupyterHub components.
#  JupyterHub will automatically create the necessary certificate authority and
#  sign notebook certificates as they're created.
#c.JupyterHub.internal_ssl = False

## The public facing ip of the whole JupyterHub application (specifically
#  referred to as the proxy).
#  
#  This is the address on which the proxy will listen. The default is to listen
#  on all interfaces. This is the only address through which JupyterHub should be
#  accessed by users.
#  
#  .. deprecated: 0.9
#      Use JupyterHub.bind_url
#c.JupyterHub.ip = ''

## Supply extra arguments that will be passed to Jinja environment.
#c.JupyterHub.jinja_environment_options = {}

## Interval (in seconds) at which to update last-activity timestamps.
#c.JupyterHub.last_activity_interval = 300

## Dict of 'group': ['usernames'] to load at startup.
#  
#  This strictly *adds* groups and users to groups.
#  
#  Loading one set of groups, then starting JupyterHub again with a different set
#  will not remove users or groups from previous launches. That must be done
#  through the API.
#c.JupyterHub.load_groups = {}

## Specify path to a logo image to override the Jupyter logo in the banner.
#c.JupyterHub.logo_file = ''

## Maximum number of concurrent named servers that can be created by a user at a
#  time.
#  
#  Setting this can limit the total resources a user can consume.
#  
#  If set to 0, no limit is enforced.
#c.JupyterHub.named_server_limit_per_user = 0

## File to write PID Useful for daemonizing JupyterHub.
#c.JupyterHub.pid_file = ''

## The public facing port of the proxy.
#  
#  This is the port on which the proxy will listen. This is the only port through
#  which JupyterHub should be accessed by users.
#  
#  .. deprecated: 0.9
#      Use JupyterHub.bind_url
#c.JupyterHub.port = 8000

## DEPRECATED since version 0.8 : Use ConfigurableHTTPProxy.api_url
#c.JupyterHub.proxy_api_ip = ''

## DEPRECATED since version 0.8 : Use ConfigurableHTTPProxy.api_url
#c.JupyterHub.proxy_api_port = 0

## DEPRECATED since version 0.8: Use ConfigurableHTTPProxy.auth_token
#c.JupyterHub.proxy_auth_token = ''

## Interval (in seconds) at which to check if the proxy is running.
c.JupyterHub.proxy_check_interval = 300

## The class to use for configuring the JupyterHub proxy.
#  
#          Should be a subclass of :class:`jupyterhub.proxy.Proxy`.
#  
#          .. versionchanged:: 1.0
#              proxies may be registered via entry points,
#              e.g. `c.JupyterHub.proxy_class = 'traefik'`
#  
#  Currently installed: 
#    - configurable-http-proxy: jupyterhub.proxy.ConfigurableHTTPProxy
#    - default: jupyterhub.proxy.ConfigurableHTTPProxy
#    - traefik_consul: jupyterhub_traefik_proxy.TraefikConsulProxy
#    - traefik_etcd: jupyterhub_traefik_proxy.TraefikEtcdProxy
#    - traefik_toml: jupyterhub_traefik_proxy.TraefikTomlProxy
#c.JupyterHub.proxy_class = 'jupyterhub.proxy.ConfigurableHTTPProxy'
c.JupyterHub.proxy_class = 'traefik_toml'
c.TraefikTomlProxy.should_start = False
c.TraefikTomlProxy.toml_static_config_file='/etc/traefik/traefik.toml'
c.TraefikTomlProxy.toml_dynamic_config_file='/etc/traefik/rules.toml'

## DEPRECATED since version 0.8. Use ConfigurableHTTPProxy.command
#c.JupyterHub.proxy_cmd = []

## Recreate all certificates used within JupyterHub on restart.
#  
#  Note: enabling this feature requires restarting all notebook servers.
#  
#  Use with internal_ssl
#c.JupyterHub.recreate_internal_certs = False

## Redirect user to server (if running), instead of control panel.
#c.JupyterHub.redirect_to_server = True

## Purge and reset the database.
#c.JupyterHub.reset_db = False

## Interval (in seconds) at which to check connectivity of services with web
#  endpoints.
c.JupyterHub.service_check_interval = 120

## Dict of token:servicename to be loaded into the database.
#  
#  Allows ahead-of-time generation of API tokens for use by externally managed
#  services.
#c.JupyterHub.service_tokens = {}

## List of service specification dictionaries.
#  
#  A service
#  
#  For instance::
#  
#      services = [
#          {
#              'name': 'cull_idle',
#              'command': ['/path/to/cull_idle_servers.py'],
#          },
#          {
#              'name': 'formgrader',
#              'url': 'http://127.0.0.1:1234',
#              'api_token': 'super-secret',
#              'environment':
#          }
#      ]
c.JupyterHub.services = [
                 {
                    'name': 'cull_idle',
                    'admin': True,
                    'command': ['python3', '/opt/tljh/hub/bin/cull_idle_servers.py', '--timeout=900'],
                 },
                 {
                    'name': 'cull_idle',
                    'admin': True,
                    'api_token': '65e67ca743cadaff51452dab016e99d38da8f2cd365758cb1dc8fa58998e47c1',
                 }
              ]

## Shuts down all user servers on logout
#c.JupyterHub.shutdown_on_logout = True

## The class to use for spawning single-user servers.
#  
#          Should be a subclass of :class:`jupyterhub.spawner.Spawner`.
#  
#          .. versionchanged:: 1.0
#              spawners may be registered via entry points,
#              e.g. `c.JupyterHub.spawner_class = 'localprocess'`
#  
#  Currently installed: 
#    - default: jupyterhub.spawner.LocalProcessSpawner
#    - localprocess: jupyterhub.spawner.LocalProcessSpawner
#    - simple: jupyterhub.spawner.SimpleLocalProcessSpawner
#c.JupyterHub.spawner_class = 'jupyterhub.spawner.LocalProcessSpawner'

## Path to SSL certificate file for the public facing interface of the proxy
#  
#  When setting this, you should also set ssl_key
c.JupyterHub.ssl_cert = '/var/local/sslcert/adyne_wildcard.crt'

## Path to SSL key file for the public facing interface of the proxy
#  
#  When setting this, you should also set ssl_cert
c.JupyterHub.ssl_key = '/var/local/sslcert/adyne_wildcard.key'

## Host to send statsd metrics to. An empty string (the default) disables sending
#  metrics.
#c.JupyterHub.statsd_host = ''

## Port on which to send statsd metrics about the hub
#c.JupyterHub.statsd_port = 8125

## Prefix to use for all metrics sent by jupyterhub to statsd
#c.JupyterHub.statsd_prefix = 'jupyterhub'

## Run single-user servers on subdomains of this host.
#  
#  This should be the full `https://hub.domain.tld[:port]`.
#  
#  Provides additional cross-site protections for javascript served by single-
#  user servers.
#  
#  Requires `<username>.hub.domain.tld` to resolve to the same host as
#  `hub.domain.tld`.
#  
#  In general, this is most easily achieved with wildcard DNS.
#  
#  When using SSL (i.e. always) this also requires a wildcard SSL certificate.
#c.JupyterHub.subdomain_host = ''

## Paths to search for jinja templates, before using the default templates.
#c.JupyterHub.template_paths = []

## Extra variables to be passed into jinja templates
#c.JupyterHub.template_vars = {}

## Extra settings overrides to pass to the tornado application.
#c.JupyterHub.tornado_settings = {}

## Trust user-provided tokens (via JupyterHub.service_tokens) to have good
#  entropy.
#  
#  If you are not inserting additional tokens via configuration file, this flag
#  has no effect.
#  
#  In JupyterHub 0.8, internally generated tokens do not pass through additional
#  hashing because the hashing is costly and does not increase the entropy of
#  already-good UUIDs.
#  
#  User-provided tokens, on the other hand, are not trusted to have good entropy
#  by default, and are passed through many rounds of hashing to stretch the
#  entropy of the key (i.e. user-provided tokens are treated as passwords instead
#  of random keys). These keys are more costly to check.
#  
#  If your inserted tokens are generated by a good-quality mechanism, e.g.
#  `openssl rand -hex 32`, then you can set this flag to True to reduce the cost
#  of checking authentication tokens.
#c.JupyterHub.trust_user_provided_tokens = False

## Names to include in the subject alternative name.
#  
#  These names will be used for server name verification. This is useful if
#  JupyterHub is being run behind a reverse proxy or services using ssl are on
#  different hosts.
#  
#  Use with internal_ssl
#c.JupyterHub.trusted_alt_names = []

## Downstream proxy IP addresses to trust.
#  
#  This sets the list of IP addresses that are trusted and skipped when
#  processing the `X-Forwarded-For` header. For example, if an external proxy is
#  used for TLS termination, its IP address should be added to this list to
#  ensure the correct client IP addresses are recorded in the logs instead of the
#  proxy server's IP address.
#c.JupyterHub.trusted_downstream_ips = []

## Upgrade the database automatically on start.
#  
#  Only safe if database is regularly backed up. Only SQLite databases will be
#  backed up to a local file automatically.
#c.JupyterHub.upgrade_db = False

## Callable to affect behavior of /user-redirect/
#  
#  Receives 4 parameters: 1. path - URL path that was provided after /user-
#  redirect/ 2. request - A Tornado HTTPServerRequest representing the current
#  request. 3. user - The currently authenticated user. 4. base_url - The
#  base_url of the current hub, for relative redirects
#  
#  It should return the new URL to redirect to, or None to preserve current
#  behavior.
#c.JupyterHub.user_redirect_hook = None

#------------------------------------------------------------------------------
# Spawner(LoggingConfigurable) configuration
#------------------------------------------------------------------------------

## Base class for spawning single-user notebook servers.
#  
#  Subclass this, and override the following methods:
#  
#  - load_state - get_state - start - stop - poll
#  
#  As JupyterHub supports multiple users, an instance of the Spawner subclass is
#  created for each user. If there are 20 JupyterHub users, there will be 20
#  instances of the subclass.

## Extra arguments to be passed to the single-user server.
#  
#  Some spawners allow shell-style expansion here, allowing you to use
#  environment variables here. Most, including the default, do not. Consult the
#  documentation for your spawner to verify!
#c.Spawner.args = []

## An optional hook function that you can implement to pass `auth_state` to the
#  spawner after it has been initialized but before it starts. The `auth_state`
#  dictionary may be set by the `.authenticate()` method of the authenticator.
#  This hook enables you to pass some or all of that information to your spawner.
#  
#  Example::
#  
#      def userdata_hook(spawner, auth_state):
#          spawner.userdata = auth_state["userdata"]
#  
#      c.Spawner.auth_state_hook = userdata_hook
#c.Spawner.auth_state_hook = None

## The command used for starting the single-user server.
#  
#  Provide either a string or a list containing the path to the startup script
#  command. Extra arguments, other than this path, should be provided via `args`.
#  
#  This is usually set if you want to start the single-user server in a different
#  python environment (with virtualenv/conda) than JupyterHub itself.
#  
#  Some spawners allow shell-style expansion here, allowing you to use
#  environment variables. Most, including the default, do not. Consult the
#  documentation for your spawner to verify!
#c.Spawner.cmd = ['jupyterhub-singleuser']

## Maximum number of consecutive failures to allow before shutting down
#  JupyterHub.
#  
#  This helps JupyterHub recover from a certain class of problem preventing
#  launch in contexts where the Hub is automatically restarted (e.g. systemd,
#  docker, kubernetes).
#  
#  A limit of 0 means no limit and consecutive failures will not be tracked.
#c.Spawner.consecutive_failure_limit = 0

## Minimum number of cpu-cores a single-user notebook server is guaranteed to
#  have available.
#  
#  If this value is set to 0.5, allows use of 50% of one CPU. If this value is
#  set to 2, allows use of up to 2 CPUs.
#  
#  **This is a configuration setting. Your spawner must implement support for the
#  limit to work.** The default spawner, `LocalProcessSpawner`, does **not**
#  implement this support. A custom spawner **must** add support for this setting
#  for it to be enforced.
#c.Spawner.cpu_guarantee = None

## Maximum number of cpu-cores a single-user notebook server is allowed to use.
#  
#  If this value is set to 0.5, allows use of 50% of one CPU. If this value is
#  set to 2, allows use of up to 2 CPUs.
#  
#  The single-user notebook server will never be scheduled by the kernel to use
#  more cpu-cores than this. There is no guarantee that it can access this many
#  cpu-cores.
#  
#  **This is a configuration setting. Your spawner must implement support for the
#  limit to work.** The default spawner, `LocalProcessSpawner`, does **not**
#  implement this support. A custom spawner **must** add support for this setting
#  for it to be enforced.
#c.Spawner.cpu_limit = None

## Enable debug-logging of the single-user server
c.Spawner.debug = False

## The URL the single-user server should start in.
#  
#  `{username}` will be expanded to the user's username
#  
#  Example uses:
#  
#  - You can set `notebook_dir` to `/` and `default_url` to `/tree/home/{username}` to allow people to
#    navigate the whole filesystem from their notebook server, but still start in their home directory.
#  - Start with `/notebooks` instead of `/tree` if `default_url` points to a notebook instead of a directory.
#  - You can set this to `/lab` to have JupyterLab start by default, rather than Jupyter Notebook.
c.Spawner.default_url = '/lab'

## Disable per-user configuration of single-user servers.
#  
#  When starting the user's single-user server, any config file found in the
#  user's $HOME directory will be ignored.
#  
#  Note: a user could circumvent this if the user modifies their Python
#  environment, such as when they have their own conda environments / virtualenvs
#  / containers.
#c.Spawner.disable_user_config = False

## Whitelist of environment variables for the single-user server to inherit from
#  the JupyterHub process.
#  
#  This whitelist is used to ensure that sensitive information in the JupyterHub
#  process's environment (such as `CONFIGPROXY_AUTH_TOKEN`) is not passed to the
#  single-user server's process.
#c.Spawner.env_keep = ['PATH', 'PYTHONPATH', 'CONDA_ROOT', 'CONDA_DEFAULT_ENV', 'VIRTUAL_ENV', 'LANG', 'LC_ALL']

## Extra environment variables to set for the single-user server's process.
#  
#  Environment variables that end up in the single-user server's process come from 3 sources:
#    - This `environment` configurable
#    - The JupyterHub process' environment variables that are whitelisted in `env_keep`
#    - Variables to establish contact between the single-user notebook and the hub (such as JUPYTERHUB_API_TOKEN)
#  
#  The `environment` configurable should be set by JupyterHub administrators to
#  add installation specific environment variables. It is a dict where the key is
#  the name of the environment variable, and the value can be a string or a
#  callable. If it is a callable, it will be called with one parameter (the
#  spawner instance), and should return a string fairly quickly (no blocking
#  operations please!).
#  
#  Note that the spawner class' interface is not guaranteed to be exactly same
#  across upgrades, so if you are using the callable take care to verify it
#  continues to work after upgrades!
#
def set_python_path(spawner):
    userlib = '/home/%s/.jupyterlab/%s/notebooks/lib' % (spawner.user.name, spawner.user.name)
    baselib = '/home/%s/.jupyterlab/prod/notebooks/lib' % spawner.user.name
    return '%s:%s' % (userlib, baselib)

def set_lab_home(spawner):
    return '/home/%s/.jupyterlab' % spawner.user.name

def set_lab_dev(spawner):
    return '/home/%s/.jupyterlab/%s' % (spawner.user.name, spawner.user.name)

def set_lab_prod(spawner):
    return '/home/%s/.jupyterlab/%s' % (spawner.user.name, 'prod')

def set_lab_data(spawner):
    return '/home/%s/.jupyterlab/%s' % (spawner.user.name, 'p_drive')

def set_lab_source(spawner):
    return '/home/%s/.jupyterlab/%s' % (spawner.user.name, 'n_drive')

## Create temp folder that notebooks can use for intermediate data
#
#  For typical users it will be of the form
#     /var/tmp/user-id
#
#  For the prod id where there may be multiple simultaneous notebooks
#  writing and reading at the same time, an extra level of uniqueness
#  consisting of the Singleserver session port number is added.  The
#  port number is extraced from the spawner url

import os
import pwd
from tornado.log import app_log
def set_lab_temp(spawner):
    path = '/var/tmp/%s' % spawner.user.name 
    if spawner.user.name.startswith('jhub'):
        url = spawner._server.url
        key = url[url.find(':',5)+1:url.find('/user')]
        path = os.path.join(path, key)
    # in case there are permission issues...
    try:
        os.makedirs(path, exist_ok=True)
        user = pwd.getpwnam(spawner.user.name)
        uid = user.pw_uid
        gid = user.pw_gid
        os.chown(path, uid, gid)
    except:
        app_log.error('Exception with %s %s directory.  Check directory permissions' % (spawner.user.name, path))
    return path

c.Spawner.environment = {
         'PYTHONPATH': set_python_path,
         'JUPYTERLAB_HOME': set_lab_home,
         # dev
         'JUPYTERLAB_DEV': set_lab_dev,
         'DEV': set_lab_dev,
         # prod
         'JUPYTERLAB_PROD': set_lab_prod,
         'PROD': set_lab_prod,
         # P drive 
         'JUPYTERLAB_DATA': set_lab_data,
         'DATA': set_lab_data,
         '_P_DRIVE': set_lab_data,
         # N drive
         'SOURCE': set_lab_source,
         '_N_DRIVE': set_lab_source,
         # TEMP
         'TEMP': set_lab_temp,
         # for alib
         'ALPHA_FS': '/mnt/asdfs/apps',
         # for volaDynamics
         'RLM_LICENSE': '/opt/volaDynamics',
         'VOLAR_TZDATA_PATH': '/opt/volaDynamics/pyvolar_data'
}

## Timeout (in seconds) before giving up on a spawned HTTP server
#  
#  Once a server has successfully been spawned, this is the amount of time we
#  wait before assuming that the server is unable to accept connections
#c.Spawner.http_timeout = 30

## The IP address (or hostname) the single-user server should listen on.
#  
#  The JupyterHub proxy implementation should be able to send packets to this
#  interface.
#c.Spawner.ip = ''

## Minimum number of bytes a single-user notebook server is guaranteed to have
#  available.
#  
#  Allows the following suffixes:
#    - K -> Kilobytes
#    - M -> Megabytes
#    - G -> Gigabytes
#    - T -> Terabytes
#  
#  **This is a configuration setting. Your spawner must implement support for the
#  limit to work.** The default spawner, `LocalProcessSpawner`, does **not**
#  implement this support. A custom spawner **must** add support for this setting
#  for it to be enforced.
#c.Spawner.mem_guarantee = None

## Maximum number of bytes a single-user notebook server is allowed to use.
#  
#  Allows the following suffixes:
#    - K -> Kilobytes
#    - M -> Megabytes
#    - G -> Gigabytes
#    - T -> Terabytes
#  
#  If the single user server tries to allocate more memory than this, it will
#  fail. There is no guarantee that the single-user notebook server will be able
#  to allocate this much memory - only that it can not allocate more than this.
#  
#  **This is a configuration setting. Your spawner must implement support for the
#  limit to work.** The default spawner, `LocalProcessSpawner`, does **not**
#  implement this support. A custom spawner **must** add support for this setting
#  for it to be enforced.
#c.Spawner.mem_limit = None

## Path to the notebook directory for the single-user server.
#  
#  The user sees a file listing of this directory when the notebook interface is
#  started. The current interface does not easily allow browsing beyond the
#  subdirectories in this directory's tree.
#  
#  `~` will be expanded to the home directory of the user, and {username} will be
#  replaced with the name of the user.
#  
#  Note that this does *not* prevent users from accessing files outside of this
#  path! They can do so with many other means.
c.Spawner.notebook_dir = '/home/{username}/.jupyterlab'

## An HTML form for options a user can specify on launching their server.
#  
#  The surrounding `<form>` element and the submit button are already provided.
#  
#  For example:
#  
#  .. code:: html
#  
#      Set your key:
#      <input name="key" val="default_key"></input>
#      <br>
#      Choose a letter:
#      <select name="letter" multiple="true">
#        <option value="A">The letter A</option>
#        <option value="B">The letter B</option>
#      </select>
#  
#  The data from this form submission will be passed on to your spawner in
#  `self.user_options`
#  
#  Instead of a form snippet string, this could also be a callable that takes as
#  one parameter the current spawner instance and returns a string. The callable
#  will be called asynchronously if it returns a future, rather than a str. Note
#  that the interface of the spawner class is not deemed stable across versions,
#  so using this functionality might cause your JupyterHub upgrades to break.
#c.Spawner.options_form = traitlets.Undefined

## Interval (in seconds) on which to poll the spawner for single-user server's
#  status.
#  
#  At every poll interval, each spawner's `.poll` method is called, which checks
#  if the single-user server is still running. If it isn't running, then
#  JupyterHub modifies its own state accordingly and removes appropriate routes
#  from the configurable proxy.
#c.Spawner.poll_interval = 30

## The port for single-user servers to listen on.
#  
#  Defaults to `0`, which uses a randomly allocated port number each time.
#  
#  If set to a non-zero value, all Spawners will use the same port, which only
#  makes sense if each server is on a different address, e.g. in containers.
#  
#  New in version 0.7.
#c.Spawner.port = 0

## An optional hook function that you can implement to do work after the spawner
#  stops.
#  
#  This can be set independent of any concrete spawner implementation.
#c.Spawner.post_stop_hook = None

## An optional hook function that you can implement to do some bootstrapping work
#  before the spawner starts. For example, create a directory for your user or
#  load initial content.
#  
#  This can be set independent of any concrete spawner implementation.
#  
#  This maybe a coroutine.
#  
#  Example::
#  
#      from subprocess import check_call
#      def my_hook(spawner):
#          username = spawner.user.name
#          check_call(['./examples/bootstrap-script/bootstrap.sh', username])
#  
#      c.Spawner.pre_spawn_hook = my_hook

from tornado.log import app_log
def clone_git_repo(user_dir, user_name):
    if os.environ.get('JUPYTERLAB_GIT_REPO'):
        app_log.info('env is: %s' % os.environ['JUPYTERLAB_GIT_REPO'])
        # git repo defined in env variable
        git_repo = os.environ['JUPYTERLAB_GIT_REPO']
        # add following env variable to disable any prompts for 
        # credentials from the git repo which would hang jupyterhub
        git_env = {'GIT_TERMINAL_PROMPT': '0'}
        # clone the Dev branch for developers to get latest commits
        cmd = ['/usr/bin/git', 'clone', '--branch', 'Dev', git_repo]
        # add timeout to prevent git process from hanging jupyterhub
        with subprocess.Popen(cmd, cwd=user_dir, env=git_env) as proc:
            try:
                # wait 45 sec then kill the subproccess
                proc.wait(45)
            except subprocess.TimeoutExpired:
                proc.kill()
                app_log.warn('Time out cloning git repo for: %s' % user_name)
                pass

import os
import shutil
def config_git_repo(home_dir, user_dir, uid, gid):
    # set up filters
    attr_dir = os.path.join(home_dir, '.config', 'git')
    attr = os.path.join(attr_dir, 'attributes')
    if not os.path.exists(attr):
        os.makedirs(attr_dir, exist_ok=True)
        shutil.copyfile('/opt/tljh/hub/share/git-config/attributes', attr)
        os.chown(attr, uid, gid)
        os.chown(os.path.join(home_dir, '.config'), uid, gid)
        os.chown(os.path.join(home_dir, '.config', 'git'), uid, gid)
       
    # set up pre-commit
    git_base = os.path.join(user_dir, 'notebooks')
    config = os.path.join(git_base, '.git', 'config')
    if not os.path.exists(config):
        shutil.copyfile('/opt/tljh/hub/share/git-config/config', config)
        os.chown(config, uid, gid)
    else:
        config_src = '/opt/tljh/hub/share/git-config'
        #  the above folder should contain key.ini files
        #  for each configuration item to be added to 
        #  a user's repo config.  The file should contain
        #  a key-value pair with the key coresponding to 
        #  the file name, e.g., for pull.ini the file 
        #  contents should be:
        #     [pull]
        #           rebase = True
        #
        with open(config, 'r') as base:
           base_config = base.read()
        with open(config, 'a') as base: 
           for file in os.listdir(config_src):
               if file.endswith('.ini'):
                   key = os.path.splitext(file)[0]
                   if key not in base_config:
                       with open(os.path.join(config_src, file)) as item:
                           base.write(item.read())
           os.chown(config, uid, gid)
    hooks_dir = os.path.join(git_base, '.git', 'hooks')
    hook = os.path.join(hooks_dir, 'pre-commit')
    if not os.path.exists(hook):
        shutil.copyfile('/opt/tljh/hub/share/git-config/pre-commit', hook)
        os.chown(hook, uid, gid)

# for first time users and will check for existing users.  Users should
# not be able to alter this structure from JupyterLab file browser, but 
# may be able to do so through the terminals whether intentionally or 
# otherwise.  In either eveent it will restore the base structure at 
# login, unless they modified the permissions, which will report an 
# error, but should otherwise allow the login to proceed.

import pwd
import subprocess
def setup_user_hook(spawner):
    try:
        username = spawner.user.name
        app_log.info('running pre_spawn_hook for user: %s' % username)
        app_log.info('path is: %s' % os.environ['PATH'])
        home_dir = os.path.join('/home', username)
        base_dir = os.path.join('/home', username, '.jupyterlab')
        user_dir = os.path.join('/mnt', 'jupyterpersonal', username)
        prod_dir = os.path.join('/mnt', 'jupytershared', 'Production')
        data_dir = os.path.join('/mnt', 'jupyterdata')
        qpfs_dir = os.path.join('/mnt', 'qpfs')
        cpnt_dir = os.path.join(user_dir, '.appmode.checkpoints')
        user = pwd.getpwnam(username)
        uid = user.pw_uid
        gid = user.pw_gid
        home = user.pw_dir
        #check if user folder exists on share...
        if not os.path.exists(base_dir):
            try:
                app_log.info('creating user base dir: %s' % base_dir)
                os.makedirs(base_dir)
                os.chown(base_dir, uid, gid)
            except Exception as ex:
                app_log.error('Exception creating base directories for user: %s' % spawner.user.name)
                app_log.exception(ex)
                pass
        # check if shared drive personal dir exists
        if not os.path.exists(user_dir):
            app_log.info('creating user shared mount: %s' % user_dir)
            os.mkdir(user_dir,  0o755)
            os.chown(user_dir, uid, gid)
            try:
                clone_git_repo(user_dir, username)
            except Exception as ex:
                app_log.error('Exception cloning jupyterhub git repository: %s' % spawner.user.name)
                app_log.exception(ex)
                pass
        # ---->
        # for now check git config for each launch 
        # move to under new user after transition perioda
        # by indenting this block 4 spaces 
        try:
            app_log.info('Git repo configuration for %s' % username)
            config_git_repo(home_dir, user_dir, uid, gid)
        except Exception as ex:
            app_log.error('Exception configuring git repository: %s' % spawner.user.name)
            app_log.exception(ex)
            pass
        # end config git block
        # ---->

        if not os.path.exists(cpnt_dir):
            os.mkdir(cpnt_dir,  0o755)
            os.chown(cpnt_dir, uid, gid)
   
        # check if sym-links exists...
        user_link = os.path.join(base_dir, username)
        prod_link = os.path.join(base_dir, 'prod')
        p_drv_link = os.path.join(base_dir, 'p_drive')
        n_drv_link = os.path.join(base_dir, 'n_drive')
        if not os.path.exists(user_link):
            app_log.info('creating dev (user-id) sym-link: %s' % user_link) 
            os.symlink(user_dir, user_link)
        if not os.path.exists(prod_link):
            app_log.info('creating prod sym-link for user: %s' % username)
            os.symlink(prod_dir, prod_link)
        if not os.path.exists(p_drv_link):
            app_log.info('creating p-drive sym-link for user: %s' % username)
            os.symlink(data_dir, p_drv_link)
        if not os.path.exists(n_drv_link):
            app_log.info('creating n-drive sym-link for user: %s' % username)
            os.symlink(qpfs_dir, n_drv_link)
    except Exception as ex:
        app_log.error('Exception settup up directories for user: %s' % spawner.user.name)
        app_log.exception(ex)
        pass
    finally:
        # change home dir ownership here in case it was left as root
        # when created.  async timing seems to be off for some new users
        # app_log.info('environment variable data: %s  alib:  %s' %(os.environ['JUPYTERLAB_DATA'], os.environ['ALPHA_FS']))
	
        if os.path.exists(home):
            app_log.info('checking user home dirctory permissions')
            app_log.info(os.system('ls -lad /home/%s' % spawner.user.name))
            os.chown(home, uid, gid)

c.Spawner.pre_spawn_hook = setup_user_hook

## List of SSL alt names
#  
#  May be set in config if all spawners should have the same value(s), or set at
#  runtime by Spawner that know their names.
#c.Spawner.ssl_alt_names = []

## Whether to include DNS:localhost, IP:127.0.0.1 in alt names
#c.Spawner.ssl_alt_names_include_local = True

## Timeout (in seconds) before giving up on starting of single-user server.
#  
#  This is the timeout for start to return, not the timeout for the server to
#  respond. Callers of spawner.start will assume that startup has failed if it
#  takes longer than this. start should return when the server process is started
#  and its location is known.
#c.Spawner.start_timeout = 60

#------------------------------------------------------------------------------
# Authenticator(LoggingConfigurable) configuration
#------------------------------------------------------------------------------

## Base class for implementing an authentication provider for JupyterHub

## Set of users that will have admin rights on this JupyterHub.
#  
#  Admin users have extra privileges:
#   - Use the admin panel to see list of users logged in
#   - Add / remove users in some authenticators
#   - Restart / halt the hub
#   - Start / stop users' single-user servers
#   - Can access each individual users' single-user server (if configured)
#  
#  Admin access should be treated the same way root access is.
#  
#  Defaults to an empty set, in which case no user has admin access.
c.Authenticator.admin_users = set(['glovas', 'hfrancisco', 'kkessler'])

## The max age (in seconds) of authentication info before forcing a refresh of
#  user auth info.
#  
#  Refreshing auth info allows, e.g. requesting/re-validating auth tokens.
#  
#  See :meth:`.refresh_user` for what happens when user auth info is refreshed
#  (nothing by default).
#c.Authenticator.auth_refresh_age = 300

## Automatically begin the login process
#  
#  rather than starting with a "Login with..." link at `/hub/login`
#  
#  To work, `.login_url()` must give a URL other than the default `/hub/login`,
#  
#  .. versionadded:: 0.8
c.Authenticator.auto_login = True

## Blacklist of usernames that are not allowed to log in.
#  
#  Use this with supported authenticators to restrict which users can not log in.
#  This is an additional blacklist that further restricts users, beyond whatever
#  restrictions the authenticator has in place.
#  
#  If empty, does not perform any additional restriction.
#  
#  .. versionadded: 0.9
#c.Authenticator.blacklist = set()

## Enable persisting auth_state (if available).
#  
#  auth_state will be encrypted and stored in the Hub's database. This can
#  include things like authentication tokens, etc. to be passed to Spawners as
#  environment variables.
#  
#  Encrypting auth_state requires the cryptography package.
#  
#  Additionally, the JUPYTERHUB_CRYPT_KEY environment variable must contain one
#  (or more, separated by ;) 32B encryption keys. These can be either base64 or
#  hex-encoded.
#  
#  If encryption is unavailable, auth_state cannot be persisted.
#  
#  New in JupyterHub 0.8
#c.Authenticator.enable_auth_state = False

## An optional hook function that you can implement to do some bootstrapping work
#  during authentication. For example, loading user account details from an
#  external system.
#  
#  This function is called after the user has passed all authentication checks
#  and is ready to successfully authenticate. This function must return the
#  authentication dict reguardless of changes to it.
#  
#  This maybe a coroutine.
#  
#  .. versionadded: 1.0
#  
#  Example::
#  
#      import os, pwd
#      def my_hook(authenticator, handler, authentication):
#          user_data = pwd.getpwnam(authentication['name'])
#          spawn_data = {
#              'pw_data': user_data
#              'gid_list': os.getgrouplist(authentication['name'], user_data.pw_gid)
#          }
#  
#          if authentication['auth_state'] is None:
#              authentication['auth_state'] = {}
#          authentication['auth_state']['spawn_data'] = spawn_data
#  
#          return authentication
#  
#      c.Authenticator.post_auth_hook = my_hook
#import os
#import pwd
#from tornado.log import app_log
def auth_hook(authenticator, handler, authentication):
    username = authentication['name']
    user = pwd.getpwnam(username)
    uid = user.pw_uid
    gid = user.pw_gid
    home = user.pw_dir

    # change home dir ownership here in case it was left 
    # as root.  timing seems to be off for new users
    if os.path.exists(home):
        app_log.info('past_auth_hook: checking user home dirctory permissions')
        app_log.info(os.system('ls -lad /home/%s' % username))
        os.chown(home, uid, gid)
    else:
        app_log.warn('post_auth_hook: home dirctory not created: %s' % username)

    return authentication

c.Authenticator.post_auth_hook = auth_hook

## Force refresh of auth prior to spawn.
#  
#  This forces :meth:`.refresh_user` to be called prior to launching a server, to
#  ensure that auth state is up-to-date.
#  
#  This can be important when e.g. auth tokens that may have expired are passed
#  to the spawner via environment variables from auth_state.
#  
#  If refresh_user cannot refresh the user auth data, launch will fail until the
#  user logs in again.
#c.Authenticator.refresh_pre_spawn = False

## Dictionary mapping authenticator usernames to JupyterHub users.
#  
#  Primarily used to normalize OAuth user names to local users.
#c.Authenticator.username_map = {}

## Regular expression pattern that all valid usernames must match.
#  
#  If a username does not match the pattern specified here, authentication will
#  not be attempted.
#  
#  If not set, allow any username.
#c.Authenticator.username_pattern = ''

## Whitelist of usernames that are allowed to log in.
#  
#  Use this with supported authenticators to restrict which users can log in.
#  This is an additional whitelist that further restricts users, beyond whatever
#  restrictions the authenticator has in place.
#  
#  If empty, does not perform any additional restriction.
#c.Authenticator.whitelist = set()

#------------------------------------------------------------------------------
# CryptKeeper(SingletonConfigurable) configuration
#------------------------------------------------------------------------------

## Encapsulate encryption configuration
#  
#  Use via the encryption_config singleton below.

## 
#c.CryptKeeper.keys = []

## The number of threads to allocate for encryption
#c.CryptKeeper.n_threads = 4
