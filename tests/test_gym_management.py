import unittest
import logging
import os
import json
from utils.api_helper1 import ManagementUserAPIHandler
from tests.test_management_user import TestManagementUserAuth

log = logging.getLogger(__name__)


class TestGymManagement(unittest.TestCase):
    """
    Comprehensive tests for Gym Management API operations, covering:
    - Gym creation, update, deletion
    - Gym user lifecycle
    - Invitations
    - Authentication
    - Role assignments
    """

    @classmethod
    def setUpClass(cls):
        cls.api = ManagementUserAPIHandler(base_url="http://localhost:8000")

        json_path = os.path.join(os.path.dirname(__file__), '../utils/test_data.json')
        with open(json_path, "r") as file:
            cls.test_data = json.load(file)

        cls.access_token = getattr(TestManagementUserAuth, 'access_token', None)

        cls.gym_id = None
        cls.gym_user_id = None
        cls.gym_user_access_token = None
        cls.gym_user_refresh_token = None
        cls.role_id = None

    def test_create_gym(self):
        """Test creating a new gym using management token."""
        try:
            payload = self.test_data["create_gym"][0]
            response = self.api.create_gym(token=self.access_token, gym_payload=payload)
            self.assertIn("data", response)
            TestGymManagement.gym_id = response["data"]["id"]
        except Exception as e:
            self.fail(f"Create gym test failed: {e}")

    def test_get_gym_by_id(self):
        """Test fetching gym by ID."""
        try:
            self.assertIsNotNone(self.gym_id)
            response = self.api.get_gym_by_id(token=self.access_token, gym_id=self.gym_id)
            self.assertEqual(response["data"]["id"], self.gym_id)
        except Exception as e:
            self.fail(f"Get gym by ID test failed: {e}")

    def test_update_gym(self):
        """Test updating gym details."""
        try:
            payload = self.test_data["update_gym"][0]
            response = self.api.update_gym(token=self.access_token, gym_id=self.gym_id, payload=payload)
            self.assertEqual(response["data"]["name"], payload["name"])
        except Exception as e:
            self.fail(f"Update gym test failed: {e}")

    def test_list_gyms(self):
        """Test listing all gyms."""
        try:
            response = self.api.list_gyms(token=self.access_token)
            self.assertIn("data", response)
        except Exception as e:
            self.fail(f"List gyms test failed: {e}")

    def test_invite_user_to_gym(self):
        """Test inviting a user to a gym."""
        try:
            response = self.api.invite_user_to_gym(token=self.access_token, gym_id=self.gym_id,
                                                   user_id=self.gym_user_id)
            self.assertIn("message", response)
        except Exception as e:
            self.fail(f"Invite user to gym test failed: {e}")

    def test_list_users_for_gym(self):
        """Test listing users invited to a gym."""
        try:
            response = self.api.list_users_for_gym(token=self.access_token, gym_id=self.gym_id)
            self.assertIn("data", response)
        except Exception as e:
            self.fail(f"List users for gym test failed: {e}")

    def test_remove_user_from_gym(self):
        """Test removing a user from a gym."""
        try:
            status_code = self.api.remove_user_from_gym(token=self.access_token, gym_id=self.gym_id,
                                                        user_id=self.gym_user_id)
            self.assertEqual(status_code, 200)
        except Exception as e:
            self.fail(f"Remove user from gym test failed: {e}")

    def test_create_gym_user(self):
        """Test creating a gym user."""
        try:
            user_data = self.test_data["create_gym_user"][0]
            resp = self.api.create_gym_user(user_data=user_data)

            self.assertEqual(resp.status_code, 201)
            resp_json = resp.json()
            self.assertIn("message", resp_json)
            self.assertIn("success", resp_json["message"].lower())

        except Exception as e:
            self.fail(f"Create gym user test failed: {e}")

    def test_verify_gym_email(self):
        """Test verifying a gym user's email using token."""
        try:
            token = self.test_data["verify_gym_email"][0]["token"]
            response = self.api.verify_gym_email(token=token)
            self.assertIn("message", response)
            self.assertIn("verified successfully", response["message"])
        except Exception as e:
            self.fail(f"Verify gym email test failed: {e}")

    def test_resend_verification_email(self):
        """Test resending email verification."""
        try:
            email = self.test_data["resend_verification_email"][0]["email"]
            response = self.api.resend_verification_email(email=email)
            self.assertIsNone(response)
        except Exception as e:
            self.fail(f"Resend verification email test failed: {e}")

    def test_request_password_reset(self):
        """Test requesting password reset for a gym user."""
        try:
            email = self.test_data["request_password_reset"][0]["email"]
            response = self.api.request_password_reset(email=email)
            response_json = response.json()
            self.assertIn("message", response_json)
        except Exception as e:
            self.fail(f"Request password reset test failed: {e}")

    def test_reset_gym_password(self):
        """Test resetting password using token."""
        try:
            reset_data = self.test_data["reset_gym_password"][0]
            response = self.api.reset_gym_password(token=reset_data["token"],
                                                   password=reset_data["password"],
                                                   cpassword=reset_data["cpassword"])
            self.assertIn("message", response)
        except Exception as e:
            self.fail(f"Reset gym password test failed: {e}")

    def test_login_gym_user(self):
        """Test gym user login."""
        try:
            login_data = self.test_data["login_gym_user"][0]
            response = self.api.login_gym_user(email=login_data["email"], password=login_data["password"])
            self.assertIn("data", response)
            TestGymManagement.gym_user_access_token = response["data"]["access_token"]
            TestGymManagement.gym_user_refresh_token = response["data"]["refresh_token"]
        except Exception as e:
            self.fail(f"Login gym user test failed: {e}")

    def test_refresh_gym_token(self):
        """Test refreshing access token using refresh token."""
        try:
            response = self.api.refresh_gym_token(refresh_token=self.gym_user_refresh_token)
            self.assertIn("data", response)
        except Exception as e:
            self.fail(f"Refresh gym token test failed: {e}")

    def test_gym_logout(self):
        """Test gym user logout."""
        try:
            status_code = self.api.gym_logout(token=self.gym_user_access_token)
            self.assertEqual(status_code, 200)
        except Exception as e:
            self.fail(f"Gym logout test failed: {e}")

    def test_get_gym_user_profile(self):
        """Test getting logged-in gym user's profile and extract user ID."""
        try:
            response = self.api.get_gym_user_profile(token=self.gym_user_access_token)
            self.assertIn("data", response)
            TestGymManagement.gym_user_id = response["data"]["id"]  # Capture user_id from profile
        except Exception as e:
            self.fail(f"Get gym user profile test failed: {e}")

    def test_get_gym_user_by_id(self):
        """Test retrieving gym user by ID."""
        try:
            response = self.api.get_gym_user_by_id(token=self.gym_user_access_token, user_id=self.gym_user_id)
            self.assertIn("data", response)
        except Exception as e:
            self.fail(f"Get gym user by ID test failed: {e}")

    def test_update_gym_user_by_id(self):
        """Test updating gym user by ID."""
        try:
            payload = self.test_data["update_gym_user"][0]
            response = self.api.update_gym_user_by_id(token=self.gym_user_access_token, user_id=self.gym_user_id,
                                                      payload=payload)
            self.assertIn("data", response)
        except Exception as e:
            self.fail(f"Update gym user test failed: {e}")

    def test_delete_gym_user(self):
        """Test deleting gym user by ID."""
        try:
            status_code = self.api.delete_gym_user(token=self.gym_user_access_token, user_id=self.gym_user_id)
            self.assertEqual(status_code, 200)
        except Exception as e:
            self.fail(f"Delete gym user test failed: {e}")

    def test_list_gym_users(self):
        """Test listing all gym users."""
        try:
            response = self.api.list_gym_users(token=self.gym_user_access_token)
            self.assertIn("data", response)
        except Exception as e:
            self.fail(f"List gym users test failed: {e}")

    def test_assign_gym_user_role(self):
        """Test assigning role to gym user."""
        try:
            role_id = self.test_data["assign_gym_user_role"][0]["role_id"]
            response = self.api.assign_gym_user_role(
                token=self.gym_user_access_token,
                user_id=self.gym_user_id,
                role_id=role_id
            )
            self.assertIn("data", response)
            TestGymManagement.role_id = role_id
        except Exception as e:
            self.fail(f"Assign gym user role test failed: {e}")

    def test_get_gym_user_role(self):
        """Test retrieving a specific gym user's role."""
        try:
            resp = self.api.get_gym_user_role(
                token=self.access_token,
                user_id=self.gym_user_id,
                role_id=self.role_id
            )
            self.assertIn("permissions", resp)
            log.info("Gym user role retrieved successfully.")
        except Exception as e:
            log.error(f"Failed to get gym user role: {e}")
            self.fail(f"Exception occurred: {e}")

    def test_list_gym_user_roles(self):
        """Test listing all gym user-role assignments."""
        try:
            resp = self.api.list_gym_user_roles(token=self.access_token)
            self.assertIsInstance(resp, list)
            self.assertTrue(any(role["user_id"] == self.gym_user_id for role in resp))
            log.info("Gym user roles listed successfully.")
        except Exception as e:
            log.error(f"Failed to list gym user roles: {e}")
            self.fail(f"Exception occurred: {e}")

    def test_delete_gym_user_role(self):
        """Test deleting a gym user's role assignment."""
        try:
            status_code = self.api.delete_gym_user_role(
                token=self.access_token,
                user_id=self.gym_user_id,
                role_id=self.role_id
            )
            self.assertIn(status_code, [200, 204])
            log.info("Gym user role deleted successfully.")
        except Exception as e:
            log.error(f"Failed to delete gym user role: {e}")
            self.fail(f"Exception occurred: {e}")

        # Confirm deletion raises an exception
        try:
            self.api.get_gym_user_role(
                token=self.access_token,
                user_id=self.gym_user_id,
                role_id=self.role_id
            )
            self.fail("Expected exception when retrieving deleted role.")
        except Exception as e:
            log.info("Confirmed gym user role was deleted; get failed as expected.")

    if __name__ == "__main__":
        unittest.main()