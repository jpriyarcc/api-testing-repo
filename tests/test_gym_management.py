import pytest
import logging
import requests
log = logging.getLogger(__name__)

gym_id = None


class TestGymManagement:
    """
    Test suite for Gym Management API operations.
    Uses a global variable `gym_id` to share the gym ID across test methods.
    Uses the `setup_user` fixture to get user_id for user-related tests.
    """

    def test_create_gym(self, api, auth_tokens, test_data):
        """
        Test creating a new gym and save the gym ID globally.

        Args:
            api: The API handler fixture.
            auth_tokens: Fixture providing access tokens.
            test_data: Fixture providing test input data.

        Raises:
            pytest.fail on test failure.
        """
        global gym_id
        try:
            payload = test_data["create_gym"][0]
            response = api.create_gym(token=auth_tokens["access_token"], gym_payload=payload)
            assert "data" in response, "'data' key missing in response"
            gym_id = response["data"]["id"]  # Save gym ID globally
        except Exception as e:
            pytest.fail(f"Create gym test failed: {e}")

    def test_get_gym_by_id(self, api, auth_tokens):
        """
        Test fetching a gym by the globally saved gym ID.

        Args:
            api: The API handler fixture.
            auth_tokens: Fixture providing access tokens.

        Raises:
            pytest.fail if gym_id is not set or test fails.
        """
        global gym_id
        try:
            assert gym_id is not None, "gym_id not set"
            response = api.get_gym_by_id(token=auth_tokens["access_token"], gym_id=gym_id)
            assert response["data"]["id"] == gym_id, "Gym ID mismatch"
        except Exception as e:
            pytest.fail(f"Get gym by ID test failed: {e}")

    def test_update_gym(self, api, auth_tokens, test_data):
        """
        Test updating gym details using the globally saved gym ID.

        Args:
            api: The API handler fixture.
            auth_tokens: Fixture providing access tokens.
            test_data: Fixture providing update data.

        Raises:
            pytest.fail if update fails or gym_id is not set.
        """
        global gym_id
        try:
            assert gym_id is not None, "gym_id not set"
            payload = test_data["update_gym"][0]
            response = api.update_gym(token=auth_tokens["access_token"], gym_id=gym_id, payload=payload)
            assert response["data"]["name"] == payload["name"], "Gym name not updated"
        except Exception as e:
            pytest.fail(f"Update gym test failed: {e}")

    def test_list_gyms(self, api, auth_tokens):
        """
        Test listing all gyms using the access token.

        Args:
            api: The API handler fixture.
            auth_tokens: Fixture providing access tokens.

        Raises:
            pytest.fail if listing gyms fails.
        """
        try:
            response = api.list_gyms(token=auth_tokens["access_token"])
            assert "data" in response, "'data' key missing in response"
        except Exception as e:
            pytest.fail(f"List gyms test failed: {e}")

    def test_invite_user_to_gym(self, api, auth_tokens, setup_user):
        """
        Test inviting a user to a gym.

        Args:
            api: The API handler fixture.
            auth_tokens: Fixture providing access tokens.
            setup_user: Fixture providing user details including user_id.

        Raises:
            pytest.fail if invitation fails.
        """
        global gym_id
        try:
            user_id = setup_user.user_id
            assert gym_id is not None, "gym_id not set"
            response = api.invite_user_to_gym(token=auth_tokens["access_token"], gym_id=gym_id, user_id=user_id)
            assert "message" in response, "'message' key missing in invite response"
        except Exception as e:
            pytest.fail(f"Invite user to gym test failed: {e}")

    def test_list_users_for_gym(self, api, auth_tokens):
        """
        Test listing users invited to a gym.

        Args:
            api: The API handler fixture.
            auth_tokens: Fixture providing access tokens.

        Raises:
            pytest.fail if listing users fails.
        """
        global gym_id
        try:
            assert gym_id is not None, "gym_id not set"
            response = api.list_users_for_gym(token=auth_tokens["access_token"], gym_id=gym_id)
            assert "data" in response, "'data' key missing in users list response"
        except Exception as e:
            pytest.fail(f"List users for gym test failed: {e}")

    def test_remove_user_from_gym(self, api, auth_tokens, setup_user):
        """
        Test removing a user from a gym.

        Args:
            api: The API handler fixture.
            auth_tokens: Fixture providing access tokens.
            setup_user: Fixture providing user details including user_id.

        Raises:
            pytest.fail if removal fails.
        """
        global gym_id
        try:
            user_id = setup_user.user_id
            assert gym_id is not None, "gym_id not set"
            status_code = api.remove_user_from_gym(token=auth_tokens["access_token"], gym_id=gym_id, user_id=user_id)
            assert status_code == 200, "User removal failed"
        except Exception as e:
            pytest.fail(f"Remove user from gym test failed: {e}")

    def test_create_gym_user(self, api, test_data):
        """Test creating a new gym user."""
        try:
            case = test_data["create_gym_user"][0]["user_data"]
            resp = api.create_gym_user(user_data=case)
            assert resp.status_code == 201
            resp_json = resp.json()
            assert "message" in resp_json
            assert "success" in resp_json["message"].lower()
        except Exception as e:
            pytest.fail(f"Create gym user test failed: {e}")

    def test_verify_gym_email(self, api, test_data):
        """Test verifying a gym user's email via verification token."""
        try:
            token = test_data["verify_gym_email"][0]["token"]
            response = api.verify_gym_email(token=token)
            assert "message" in response
            assert "verified successfully" in response["message"]
        except Exception as e:
            pytest.fail(f"Verify gym email test failed: {e}")

    def test_resend_verification_email(self, api, test_data):
        """Test resending the verification email to a gym user."""
        email = test_data["resend_verification_email"][0]["email"]
        try:
            response = api.resend_verification_email(email=email)

            assert response.status_code == 200
            resp_json = response.json()
            assert "message" in resp_json
            assert "sent" in resp_json["message"].lower()
        except requests.exceptions.HTTPError as e:

            if e.response.status_code == 400:
                resp_json = e.response.json()

                assert "already verified" in resp_json.get("message", "").lower()
            else:
                pytest.fail(f"Unexpected error: {e}")

    def test_request_password_reset(self, api, test_data):
        """Test requesting a password reset email for a gym user."""
        try:
            email = test_data["request_password_reset"][0]["email"]
            response = api.request_password_reset(email=email)
            response_json = response.json()
            assert "message" in response_json
        except Exception as e:
            pytest.fail(f"Request password reset test failed: {e}")

    def test_reset_gym_password(self, api, test_data):
        """Test resetting a gym user's password using a reset token."""
        try:
            reset_data = test_data["reset_gym_password"][0]
            response = api.reset_gym_password(
                token=reset_data["token"],
                password=reset_data["password"],
                cpassword=reset_data["cpassword"],
            )
            assert "message" in response
        except Exception as e:
            pytest.fail(f"Reset gym password test failed: {e}")

    def test_login_gym_user(self, api, test_data, gym_auth_tokens):
        """Test gym user login and validate received tokens."""
        try:
            assert "access_token" in gym_auth_tokens
            assert "refresh_token" in gym_auth_tokens
        except Exception as e:
            pytest.fail(f"Login gym user test failed: {e}")

    def test_refresh_gym_token(self, api, gym_auth_tokens):
        """Test refreshing the gym user's access token using the refresh token."""
        try:
            response = api.refresh_gym_token(refresh_token=gym_auth_tokens["refresh_token"])
            assert "data" in response
        except Exception as e:
            pytest.fail(f"Refresh gym token test failed: {e}")

    def test_gym_logout(self, api, gym_auth_tokens):
        """Test logging out the gym user."""
        try:
            resp = api.gym_logout(token=gym_auth_tokens["access_token"])
            assert resp["message"] == "Logout successful"
        except Exception as e:
            pytest.fail(f"Gym logout test failed: {e}")

    def test_get_gym_user_profile(self, api, gym_auth_tokens, gym_user_id):
        """Test retrieving the logged-in gym user's profile."""
        try:
            response = api.get_gym_user_profile(token=gym_auth_tokens["access_token"])
            assert "data" in response
            assert response["data"]["id"] == gym_user_id
        except Exception as e:
            pytest.fail(f"Get gym user profile test failed: {e}")

    def test_get_gym_user_by_id(self, api, gym_auth_tokens, gym_user_id):
        """Test retrieving a gym user by their user ID."""
        try:
            response = api.get_gym_user_by_id(token=gym_auth_tokens["access_token"], user_id=gym_user_id)
            assert "data" in response
        except Exception as e:
            pytest.fail(f"Get gym user by ID test failed: {e}")

    def test_update_gym_user_by_id(self, api, test_data, gym_auth_tokens, gym_user_id):
        """Test updating gym user details by user ID."""
        try:
            payload = test_data["update_gym_user"][0]
            response = api.update_gym_user_by_id(token=gym_auth_tokens["access_token"],
                                                 user_id=gym_user_id,
                                                 payload=payload)
            assert "data" in response
        except Exception as e:
            pytest.fail(f"Update gym user test failed: {e}")

    def test_delete_gym_user(self, api, gym_auth_tokens, gym_user_id):
        """Test deleting a gym user by their user ID."""
        try:
            status_code = api.delete_gym_user(token=gym_auth_tokens["access_token"], user_id=gym_user_id)
            assert status_code == 200
        except Exception as e:
            pytest.fail(f"Delete gym user test failed: {e}")

    def test_list_gym_users(self, api, gym_auth_tokens):
        """Test listing all gym users."""
        try:
            response = api.list_gym_users(token=gym_auth_tokens["access_token"])
            assert "data" in response
        except Exception as e:
            pytest.fail(f"List gym users test failed: {e}")

    def test_assign_gym_user_role(self, api, test_data, gym_auth_tokens, gym_user_id):
        """Test assigning a role to a gym user."""
        try:
            role_id = test_data["assign_gym_user_role"][0]["role_id"]
            response = api.assign_gym_user_role(token=gym_auth_tokens["access_token"],
                                                user_id=gym_user_id,
                                                role_id=role_id)
            assert "data" in response
            self.role_id = role_id
        except Exception as e:
            pytest.fail(f"Assign gym user role test failed: {e}")

    def test_get_gym_user_role(self, api, gym_auth_tokens, gym_user_id):
        """Test retrieving a specific gym user's role."""
        try:
            role_id = getattr(self, "role_id", None)
            assert role_id is not None, "Role ID must be assigned first"
            resp = api.get_gym_user_role(token=gym_auth_tokens["access_token"],
                                         user_id=gym_user_id,
                                         role_id=role_id)
            assert "permissions" in resp
            log.info("Gym user role retrieved successfully.")
        except Exception as e:
            log.error(f"Failed to get gym user role: {e}")
            pytest.fail(f"Exception occurred: {e}")

    def test_list_gym_user_roles(self, api, gym_auth_tokens, gym_user_id):
        """Test listing all roles assigned to gym users."""
        try:
            resp = api.list_gym_user_roles(token=gym_auth_tokens["access_token"])
            assert isinstance(resp, list)
            assert any(role["user_id"] == gym_user_id for role in resp)
            log.info("Gym user roles listed successfully.")
        except Exception as e:
            log.error(f"Failed to list gym user roles: {e}")
            pytest.fail(f"Exception occurred: {e}")

    def test_delete_gym_user_role(self, api, gym_auth_tokens, gym_user_id):
        """Test deleting a gym user's assigned role."""
        try:
            role_id = getattr(self, "role_id", None)
            assert role_id is not None, "Role ID must be assigned first"
            status_code = api.delete_gym_user_role(token=gym_auth_tokens["access_token"],
                                                   user_id=gym_user_id,
                                                   role_id=role_id)
            assert status_code in [200, 204]
            log.info("Gym user role deleted successfully.")
        except Exception as e:
            log.error(f"Failed to delete gym user role: {e}")
            pytest.fail(f"Exception occurred: {e}")

        try:
            api.get_gym_user_role(token=gym_auth_tokens["access_token"],
                                  user_id=gym_user_id,
                                  role_id=role_id)
            pytest.fail("Expected exception when retrieving deleted role.")
        except Exception:
            log.info("Confirmed gym user role was deleted; retrieval failed as expected.")

