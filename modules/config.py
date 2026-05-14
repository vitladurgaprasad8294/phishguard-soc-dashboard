import os
from dotenv import load_dotenv


load_dotenv()


def _from_streamlit_secrets(key):
    """
    Read from Streamlit secrets when deployed.
    Safe fallback if Streamlit secrets are unavailable.
    """
    try:
        import streamlit as st
        try:
            if key in st.secrets:
                return st.secrets[key]
        except Exception:
            return None
    except Exception:
        return None

    return None


def get_config(key, default=""):
    """
    Priority:
    1. Streamlit Cloud secrets
    2. Local .env / environment variables
    3. Default value
    """
    secret_value = _from_streamlit_secrets(key)
    if secret_value is not None:
        return str(secret_value)

    env_value = os.getenv(key)
    if env_value is not None:
        return str(env_value)

    return str(default)


def is_enabled(key, default="false"):
    return get_config(key, default).strip().lower() in ["1", "true", "yes", "y", "on"]
