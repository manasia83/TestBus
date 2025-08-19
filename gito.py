import os
import json
import requests
import streamlit as st
from authlib.integrations.requests_client import OAuth2Session

# =====================
# Configuration (GitHub)
# =====================
# Set these in your shell before running:
#   export GITHUB_CLIENT_ID="YOUR_GITHUB_CLIENT_ID"
#   export GITHUB_CLIENT_SECRET="YOUR_GITHUB_CLIENT_SECRET"
#   export REDIRECT_URI="http://localhost:8501"
# Then run: streamlit run app_github.py
CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:8501")

# GitHub OAuth 2.0 endpoints
AUTHORIZATION_ENDPOINT = "https://github.com/login/oauth/authorize"
TOKEN_ENDPOINT = "https://github.com/login/oauth/access_token"
USER_ENDPOINT = "https://api.github.com/user"
EMAILS_ENDPOINT = "https://api.github.com/user/emails"
SCOPE = "read:user user:email"

st.set_page_config(page_title="Streamlit OAuth (GitHub)", page_icon="🐙", layout="centered")

# =====================
# Helpers
# =====================

def build_oauth_client(state: str | None = None) -> OAuth2Session:
    session = OAuth2Session(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        scope=SCOPE,
        redirect_uri=REDIRECT_URI,
        state=state,
    )
    return session

def require_configured():
    missing = []
    if not CLIENT_ID:
        missing.append("GITHUB_CLIENT_ID")
    if not CLIENT_SECRET:
        missing.append("GITHUB_CLIENT_SECRET")
    if not REDIRECT_URI:
        missing.append("REDIRECT_URI")
    if missing:
        st.error("Missing configuration: " + ", ".join(missing) + " — please export them before running.")
        st.stop()

def clear_query_params():
    try:
        st.query_params.clear()
    except Exception:
        st.experimental_set_query_params()

def get_user_and_email(access_token: str) -> dict:
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github+json",
    }
    # Basic profile
    u = requests.get(USER_ENDPOINT, headers=headers, timeout=20)
    u.raise_for_status()
    user = u.json()

    # Try to fetch primary, verified email (may be None if not public/granted)
    email = user.get("email")
    try:
        e = requests.get(EMAILS_ENDPOINT, headers=headers, timeout=20)
        if e.status_code == 200:
            emails = e.json()
            primary_verified = next((x for x in emails if x.get("primary") and x.get("verified")), None)
            if primary_verified and primary_verified.get("email"):
                email = primary_verified["email"]
    except Exception:
        pass

    user["resolved_email"] = email
    return user

# =====================
# UI
# =====================

st.title("🐙 Streamlit OAuth (GitHub)")
st.caption("Authorization Code flow with Authlib + GitHub OAuth (no OIDC)")

require_configured()

if "oauth_token" not in st.session_state:
    st.session_state["oauth_token"] = None
if "oauth_state" not in st.session_state:
    st.session_state["oauth_state"] = None

qp = st.query_params if hasattr(st, "query_params") else st.experimental_get_query_params()
auth_code = qp.get("code") if isinstance(qp.get("code"), str) else (qp.get("code", [None])[0])
auth_state = qp.get("state") if isinstance(qp.get("state"), str) else (qp.get("state", [None])[0])

if auth_code and auth_state and not st.session_state["oauth_token"]:
    with st.spinner("Exchanging authorization code for access token..."):
        try:
            if st.session_state["oauth_state"] and auth_state != st.session_state["oauth_state"]:
                st.error("State mismatch. Please try logging in again.")
            else:
                client = build_oauth_client(state=auth_state)
                token = client.fetch_token(
                    TOKEN_ENDPOINT,
                    code=auth_code,
                    headers={"Accept": "application/json"},
                    include_client_id=True,
                )
                st.session_state["oauth_token"] = token
                clear_query_params()
        except Exception as e:
            st.error(f"Token exchange failed: {e}")

if st.session_state["oauth_token"]:
    token = st.session_state["oauth_token"]
    st.success("You are signed in with GitHub ✅")

    # Fetch profile
    profile = None
    try:
        access_token = token.get("access_token")
        if not access_token:
            raise RuntimeError("No access_token in token response")
        profile = get_user_and_email(access_token)
    except Exception as e:
        st.error(f"Failed to fetch user profile: {e}")

    if profile:
        col1, col2 = st.columns([1,3])
        with col1:
            avatar = profile.get("avatar_url")
            if avatar:
                st.image(avatar, caption=profile.get("login",""))
        with col2:
            st.write("**Name:**", profile.get("name") or profile.get("login"))
            st.write("**Username:**", profile.get("login"))
            email = profile.get("resolved_email") or "—"
            st.write("**Email:**", email)
            st.write("**Profile:**", profile.get("html_url"))
            with st.expander("Raw profile JSON"):
                st.code(json.dumps(profile, indent=2))

    st.divider()
    if st.button("Log out (local)"):
        st.session_state["oauth_token"] = None
        st.session_state["oauth_state"] = None
        st.success("Signed out locally.")
else:
    st.info("You are not signed in.")
    client = build_oauth_client()
    try:
        auth_url, state = client.create_authorization_url(AUTHORIZATION_ENDPOINT)
        st.session_state["oauth_state"] = state
        st.link_button("Sign in with GitHub", auth_url, use_container_width=True)
    except Exception as e:
        st.error(f"Failed to create authorization URL: {e}")

st.caption("Note: GitHub OAuth does not issue an ID token. We call the REST API to obtain the user profile and email.")
