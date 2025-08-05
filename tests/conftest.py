# tests/conftest.py

import os
import json
import pytest
import logging
from tests.utils.api_helper1 import ManagementUserAPIHandler


log = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def api():
    """Provides API handler instance."""
    return ManagementUserAPIHandler(base_url="http://localhost:8000")


@pytest.fixture(scope="session")
def test_data():
    """Load and return test data from JSON."""
    try:
        json_path = os.path.join(os.path.dirname(__file__), 'utils/test_data.json')
        with open(json_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        pytest.fail(f"Failed to load test data: {e}")


@pytest.fixture(scope="session")
def auth_tokens(api, test_data):
    """
    Fixture to log in once per test session and provide access and refresh tokens.
    """
    try:
        case = test_data["login"][0]
        response = api.login(email=case["email"], password=case["password"])
        response_json = response.json()
        assert "data" in response_json, "Login response missing 'data' key"

        access_token = response_json["data"]["access_token"]
        refresh_token = response_json["data"]["refresh_token"]

        assert access_token, "Access token missing"
        assert refresh_token, "Refresh token missing"

        return {
            "access_token": access_token,
            "refresh_token": refresh_token
        }

    except Exception as e:
        log.error(f"Login fixture setup failed: {e}")
        pytest.fail(f"Login fixture setup failed: {e}")


@pytest.fixture(scope="session")
def setup_user(api, auth_tokens):
    """
    Fixture to fetch current user ID using access token.
    Returns a dict with user_id and access_token.
    """
    token = auth_tokens["access_token"]
    response = api.get_current_user(token=token)
    assert "data" in response, "Missing 'data' in current user response"
    user_data = response["data"]
    user_id = user_data.get("id")
    assert user_id is not None, "User ID missing in user data"

    return {"user_id": user_id, "access_token": token}


@pytest.fixture(scope="session")
def setup_role(api, auth_tokens, test_data):
    """
    Fixture to create a role and return its role_id.
    """
    token = auth_tokens["access_token"]
    try:
        role_payload = test_data.get("role")[0]
        response = api.create_role(token=token, role_data=role_payload)
        assert "data" in response, "Role creation response missing 'data'"
        role_id = response["data"].get("id")
        assert role_id, "Role ID missing in response"
        return role_id
    except Exception as e:
        log.error(f"Role setup failed: {e}")
        pytest.fail(f"Role setup failed: {e}")


@pytest.fixture(scope="session")
def gym_auth_tokens(api, test_data):
    """
    Fixture to log in as an existing gym user once per test session,
    returning gym access and refresh tokens.
    """
    try:
        login_data = test_data["login_gym_user"][0]
        response = api.login_gym_user(email=login_data["email"], password=login_data["password"])
        assert "data" in response, "Login response missing 'data' key"

        access_token = response["data"]["access_token"]
        refresh_token = response["data"]["refresh_token"]

        assert access_token, "Gym access token missing"
        assert refresh_token, "Gym refresh token missing"

        return {
            "access_token": access_token,
            "refresh_token": refresh_token
        }

    except Exception as e:
        log.error(f"Gym login fixture setup failed: {e}")
        pytest.fail(f"Gym login fixture setup failed: {e}")


@pytest.fixture(scope="session")
def gym_user_id(api, gym_auth_tokens):
    """
    Fixture to get gym user ID for the logged-in gym user.
    """
    try:
        token = gym_auth_tokens["access_token"]
        profile_resp = api.get_gym_user_profile(token=token)
        assert "data" in profile_resp, "Failed to get gym user profile"
        user_id = profile_resp["data"].get("id")
        assert user_id is not None, "Gym user ID missing from profile"
        return user_id

    except Exception as e:
        log.error(f"Fetching gym user ID fixture failed: {e}")
        pytest.fail(f"Fetching gym user ID fixture failed: {e}")
