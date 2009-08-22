from django.contrib.auth.models import User, AnonymousUser
from django.conf import settings
import django_pipes as pipes

SSO_SESSION_KEY = '_sso_user_id'

def fetch_user(user_id):
    """
    download a json blob of the user object from the master auth server
    """
    class UserApi(pipes.Pipe):
        uri = "http://localhost/api/user.json"

        @staticmethod
        def fetch(user_id):
            return UserApi.objects.get({'id': user_id})

    return UserApi.fetch(user_id).items

def load_user(user_id):
    """
    load the user from the local database, if it doesn't exist clone
    the user from the master auth server
    """
    
    # FIXME: load_user should re-download user info if it is stale
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        data = fetch_user(user_id)
        user = User(id=data['id'], username=data['username'], email=data['email'])
        user.save()
    return user

def read_sso_cookie(request):
    return request.COOKIES['sso'].split('|')[0]


def validate_session(request):
    """
    handle any sso login changes that should affect the session
    """
    
    try:
        user_id = read_sso_cookie(request)
    except:
        user_id = None

    # If a session has been previously configured
    if SSO_SESSION_KEY in request.session:
        # If the user is authenticated but a different user has signed in
        if user_id:
            if request.session[SSO_SESSION_KEY] != user_id:
                request.session.flush()
                request.session[SSO_SESSION_KEY] = user_id
        # If the user has signed out and then come back to client site
        else:
            request.session.flush()
    # If not, then configure one.
    else:
        request.session_cycle_key()
        request.session[SSO_SESSION_KEY] = user_id


class LazyUser(object):
    def __get__(self, request, obj_type=None):
        if not hasattr(request, '_cached_user'):
            try:
                user_id = read_sso_cookie(request)
                # FIXME: verify signature
                user = load_user(user_id)
            except Exception, e:
                user = AnonymousUser()

            request._cached_user = user
        return request._cached_user

# FIXME: rename to SSOAuthenticationMiddleware or similar
class AuthMiddleware(object):
    def process_request(self, request):
        request.__class__.user = LazyUser()

        validate_session(request)
        return None
