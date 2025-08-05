# tests/test_auth.py

import pytest
import logging
from tests.utils.api_data import ManagementUserCreate
log = logging.getLogger(__name__)


class TestManagementUserAuth:

    def test_register_user(self, api, test_data):
        """Test registering a new management user."""
        try:
            case = test_data["register_user"][0]
            user = ManagementUserCreate(email=case["email"], password=case["password"])

            response = api.register_user(user)
            assert response.status_code == case["expected_status"], (
                f"Expected status {case['expected_status']}, got {response.status_code}"
            )

            response_json = response.json()

            if case["expected_status"] == 201:
                assert "data" in response_json, "'data' key not found"
                assert response_json["data"]["email"] == case["email"]
            else:
                assert response_json.get("error_code") == case["expected_error_code"]

        except Exception as e:
            log.error(f"Register user test failed: {e}")
            pytest.fail(str(e))

    def test_verify_email(self, api, test_data):
        """Test verifying a user's email using the verification token."""
        try:
            case = test_data["verify_email"][0]
            response = api.verify_email(token=case["token"])
            assert response.status_code == case["expected_status"]
            response_json = response.json()
            assert case["expected_key"] in response_json
            assert response_json[case["expected_key"]] == case["expected_value"]
        except Exception as e:
            log.error(f"Verify email test failed: {e}")
            pytest.fail(str(e))

    def test_resend_verification(self, api, test_data):
        """Test resending a verification email to the user."""
        try:
            case = test_data["resend_verification"][0]
            response = api.resend_verification(email=case["email"])
            assert response.status_code == case["expected_status"]
            response_json = response.json()
            assert case["expected_key"] in response_json
            assert response_json[case["expected_key"]] == case["expected_value"]
        except Exception as e:
            log.error(f"Resend verification test failed: {e}")
            pytest.fail(str(e))

    def test_forgot_password(self, api, test_data):
        """Test initiating forgot password flow (sending reset link)."""
        try:
            case = test_data["forgot_password"][0]
            response = api.forgot_password(email=case["email"])
            assert response.status_code == case["expected_status"]
            response_json = response.json()
            assert case["expected_key"] in response_json
            assert response_json[case["expected_key"]] == case["expected_value"]
        except Exception as e:
            log.error(f"Forgot password test failed: {e}")
            pytest.fail(str(e))

    def test_reset_password(self, api, test_data):
        """Test resetting the user's password using reset token."""
        try:
            case = test_data["reset_password"][0]
            response = api.reset_password(
                token=case["token"],
                password=case["password"],
                cpassword=case["cpassword"]
            )
            assert case["expected_key"] in response
            assert response[case["expected_key"]] == case["expected_value"]
        except Exception as e:
            log.error(f"Reset password test failed: {e}")
            pytest.fail(str(e))

    def test_refresh_token(self, api, auth_tokens):
        try:
            response = api.refresh_token(refresh_token=auth_tokens["refresh_token"])
            if hasattr(response, "json"):
                response_json = response.json()
            else:
                response_json = response

            assert "data" in response_json
            assert "access_token" in response_json["data"]
        except Exception as e:
            pytest.fail(f"Refresh token test failed: {e}")

    def test_logout_user(self, api, auth_tokens):
        try:
            token = auth_tokens["access_token"]
            assert token, "Access token is missing!"
            response_json = api.logout_user(token=token)
            assert "message" in response_json
        except Exception as e:
            pytest.fail(f"Logout user test failed: {e}")

    def test_get_user_by_id(self, api, setup_user):
        try:
            user_id = setup_user.user_id
            token = setup_user.access_token
            response = api.get_user_by_id(user_id=user_id, token=token)
            assert "data" in response
            assert response["data"]["id"] == user_id
        except Exception as e:
            log.error(f"Get user by ID test failed: {e}")
            pytest.fail(str(e))

    def test_update_user_by_id(self, api, setup_user):
        """Test updating a user's profile details by user ID."""
        try:
            update_payload = {"first_name": "Updated", "last_name": "User"}
            user_id = setup_user.user_id
            token = setup_user.access_token

            response = api.update_user_by_id(
                user_id=user_id,
                token=token,
                update_payload=update_payload
            )
            assert "data" in response

            log.info("Update response data:", response["data"])

            assert response["data"].get("first_name") == update_payload["first_name"]
            assert response["data"].get("last_name") == update_payload["last_name"]

        except Exception as e:
            log.error(f"Update user test failed: {e}")
            pytest.fail(str(e))

    def test_delete_user_by_id(self, api, setup_user):
        """Test deleting a user by ID using access token and user ID from fixture."""
        try:
            user_id = setup_user.user_id
            token = setup_user.access_token

            assert user_id, "User ID is missing from setup_user fixture"
            assert token, "Access token is missing from setup_user fixture"

            response = api.delete_user_by_id(
                user_id=user_id,
                token=token
            )
            log.info("Delete user response:", response)
            assert response.get("status") == 200 or response.get("message") == "User deleted successfully"

        except Exception as e:
            log.error(f"Delete user test failed: {e}")
            pytest.fail(str(e))

    def test_list_management_users(self, api, setup_user):
        """Test retrieving a list of all management users."""
        try:
            token = setup_user.access_token

            assert token, "Access token missing in setup_user fixture"

            response = api.list_management_users(token=token)
            assert "data" in response
            assert isinstance(response["data"], list)

        except Exception as e:
            log.error(f"List management users test failed: {e}")
            pytest.fail(str(e))

