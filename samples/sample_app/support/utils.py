import os


def strtobool(value: str | None) -> bool:
    if value is None:
        return False
    value = value.lower()
    if value in ("y", "yes", "on", "1", "true", "t"):
        return True
    return False


def getenv_or_raise_exception(varname: str) -> str:
    """
    Retrieve an environment variable that MUST be set or raise an appropriate exception.
    """
    env = os.getenv(varname)

    if env is None:
        raise EnvironmentError(f"Environment variable {varname} is not set!")

    return env
