from auth0_oauth_client.errors import Auth0OauthClientImproperlyConfigured


def setting(name, default=None):
    """
    Helper function to get a Django setting by name. If setting doesn't exist it will return a default.
    """
    from django.conf import settings

    return getattr(settings, name, default)


def required_setting(name):
    """
    Helper function to get a Django setting by name. If setting doesn't exist it will raise error.
    """
    from django.conf import settings

    value = getattr(settings, name, None)
    if value is None or value == "":
        raise Auth0OauthClientImproperlyConfigured(f"The defined {name} is not valid!")
    return value


def read_required_key(config: dict, key):
    value = config.get(key)
    if value is None or value == "":
        raise Auth0OauthClientImproperlyConfigured(f"The defined {key} is not valid!")
    return value


def import_setting(name):
    from django.utils.module_loading import import_string

    module_to_import = setting(name)
    if module_to_import is None:
        return None
    return import_string(module_to_import)
