import os
import json
import requests
import streamlit as st
from authlib.integrations.requests_client import OAuth2Session


CLIENT_ID =  "CLIENT_ID"
CLIENT_SECRET = "CLIENT_SECRET"
REDIRECT_URI = "http://localhost:8501"

# Google OpenID Connect endpoints
AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
USERINFO_ENDPOINT = "https://openidconnect.googleapis.com/v1/userinfo"
SCOPE = "openid email profile"

st.set_page_config(page_title="Streamlit OAuth (Google)", page_icon="🔐", layout="centered")

# =====================
# Helpers
# =====================

def build_oauth_client(state: str | None = None) -> OAuth2Session:
    return OAuth2Session(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        scope=SCOPE,
        redirect_uri=REDIRECT_URI,
        state=state,
    )

def require_configured():
    missing = []
    if not CLIENT_ID:
        missing.append("GOOGLE_CLIENT_ID")
    if not CLIENT_SECRET:
        missing.append("GOOGLE_CLIENT_SECRET")
    if not REDIRECT_URI:
        missing.append("REDIRECT_URI")
    if missing:
        st.error(
            "Missing configuration: " + ", ".join(missing) +
            " — please export them before running."
        )
        st.stop()

def clear_query_params():
    try:
        st.query_params.clear()
    except Exception:
        st.experimental_set_query_params()

# =====================
# UI
# =====================

st.title("🔐 Streamlit OAuth (Google)")
st.caption("Authorization Code flow with Authlib + Google OpenID Connect")

require_configured()

if "oauth_token" not in st.session_state:
    st.session_state["oauth_token"] = None
if "oauth_state" not in st.session_state:
    st.session_state["oauth_state"] = None

qp = st.query_params if hasattr(st, "query_params") else st.experimental_get_query_params()
auth_code = qp.get("code") if isinstance(qp.get("code"), str) else (qp.get("code", [None])[0])
auth_state = qp.get("state") if isinstance(qp.get("state"), str) else (qp.get("state", [None])[0])

if auth_code and auth_state and not st.session_state["oauth_token"]:
    with st.spinner("Exchanging authorization code for tokens..."):
        try:
            if st.session_state["oauth_state"] and auth_state != st.session_state["oauth_state"]:
                st.error("State mismatch. Please try logging in again.")
            else:
                client = build_oauth_client(state=auth_state)
                token = client.fetch_token(
                    TOKEN_ENDPOINT,
                    code=auth_code,
                    grant_type="authorization_code",
                )
                # token is a dict like: {'access_token': '...', 'expires_in': 3599, 'scope': '...', 'token_type': 'Bearer', 'id_token': '...'}
                st.session_state["oauth_token"] = token
                clear_query_params()
        except Exception as e:
            st.error(f"Token exchange failed: {e}")

if st.session_state["oauth_token"]:
    token = st.session_state["oauth_token"]
    st.success("You are signed in with Google ✅")

    # --- Robust userinfo fetch: use explicit Bearer header ---
    profile = None
    try:
        access_token = token.get("access_token")
        if not access_token:
            raise RuntimeError("No access_token in token response")
        headers = {"Authorization": f"Bearer {access_token}"}
        resp = requests.get(USERINFO_ENDPOINT, headers=headers, timeout=20)
        resp.raise_for_status()
        profile = resp.json()
    except Exception as e:
        st.error(f"Failed to fetch user profile: {e}")
        # As a fallback, try Authlib client with token set on the session
        try:
            client = build_oauth_client()
            client.token = token
            resp2 = client.get(USERINFO_ENDPOINT)
            resp2.raise_for_status()
            profile = resp2.json()
            st.info("Fetched profile via fallback client method.")
        except Exception as e2:
            st.error(f"Fallback also failed: {e2}")

    if profile:
        col1, col2 = st.columns([1,3])
        with col1:
            picture = profile.get("picture")
            if picture:
                st.image(picture, caption=profile.get("name", ""))
        with col2:
            st.write("**Name:**", profile.get("name"))
            st.write("**Email:**", profile.get("email"))
            st.write("**Subject:**", profile.get("sub"))
            with st.expander("Raw profile JSON"):
                st.code(json.dumps(profile, indent=2))

    st.divider()
    if st.button("Log out"):
        st.session_state["oauth_token"] = None
        st.session_state["oauth_state"] = None
        st.success("Signed out locally.")
else:
    st.info("You are not signed in.")
    client = build_oauth_client()
    try:
        auth_url, state = client.create_authorization_url(
            AUTHORIZATION_ENDPOINT,
            access_type="offline",
            prompt="consent",
            include_granted_scopes="true",
        )
        st.session_state["oauth_state"] = state
        st.link_button("Sign in with Google", auth_url, use_container_width=True)
    except Exception as e:
        st.error(f"Failed to create authorization URL: {e}")

st.caption("Note: This demo stores tokens only in Streamlit session_state. For production, use encrypted server-side storage and implement token refresh & revocation.")
