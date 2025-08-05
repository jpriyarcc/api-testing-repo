import unittest
import os
import json
from utils.api_data import ManagementUserCreate
from utils.api_helper1 import ManagementUserAPIHandler
import logging

log = logging.getLogger(__name__)


class TestManagementUserAuth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Set up API handler and load test data before running test cases.
        Initializes API client, loads JSON test data, and sets default variables.
        """
        try:
            cls.api = ManagementUserAPIHandler(base_url="http://localhost:8000")
            json_path = os.path.join(os.path.dirname(__file__), '../utils/test_data.json')
            print(f"[DEBUG] Loading test data from: {json_path}")

            with open(json_path, "r") as file:
                cls.test_data = json.load(file)

            print(f"[DEBUG] Loaded keys in test_data: {list(cls.test_data.keys())}")

            cls.email = cls.test_data["login"][0]["email"]
            cls.password = cls.test_data["login"][0]["password"]
            cls.access_token = None
            cls.refresh_token = None
            cls.user_id = None
        except Exception as e:
            log.error(f"Setup failed: {e}")
            raise

    def test_register_user(self):
        """Test registering a new management user."""
        try:
            case = self.test_data["register_user"][0]
            user = ManagementUserCreate(email=case["email"], password=case["password"])
            response = self.api.register_user(user)
            self.assertIsInstance(response, dict)

            if case["expected_status"] == 201:
                self.assertIn("data", response)
                self.assertEqual(response["data"]["email"], case["email"])
            else:
                self.assertEqual(response.get("error_code"), case["expected_error_code"])
        except Exception as e:
            log.error(f"Register user test failed: {e}")
            self.fail(f"Register user test failed: {e}")

    def test_verify_email(self):
        """Test verifying a user's email using the verification token."""
        try:
            case = self.test_data["verify_email"][0]
            response = self.api.verify_email(token=case["token"])
            self.assertIsInstance(response, dict)
            self.assertIn(case["expected_key"], response)
            self.assertEqual(response[case["expected_key"]], case["expected_value"])
        except Exception as e:
            log.error(f"Verify email test failed: {e}")
            self.fail(f"Verify email test failed: {e}")

    def test_resend_verification(self):
        """Test resending a verification email to the user."""
        try:
            case = self.test_data["resend_verification"][0]
            response = self.api.resend_verification(email=case["email"])
            self.assertIsInstance(response, dict)
            self.assertIn(case["expected_key"], response)
            self.assertEqual(response[case["expected_key"]], case["expected_value"])
        except Exception as e:
            log.error(f"Resend verification test failed: {e}")
            self.fail(f"Resend verification test failed: {e}")

    def test_forgot_password(self):
        """Test initiating forgot password flow (sending reset link)."""
        try:
            case = self.test_data["forgot_password"][0]
            response = self.api.forgot_password(email=case["email"])
            self.assertIsInstance(response, dict)
            self.assertIn(case["expected_key"], response)
            self.assertEqual(response[case["expected_key"]], case["expected_value"])
        except Exception as e:
            log.error(f"Forgot password test failed: {e}")
            self.fail(f"Forgot password test failed: {e}")

    def test_reset_password(self):
        """Test resetting the user's password using reset token."""
        try:
            case = self.test_data["reset_password"][0]
            response = self.api.reset_password(
                token=case["token"],
                password=case["password"],
                cpassword=case["cpassword"]
            )
            self.assertIsInstance(response, dict)
            self.assertIn(case["expected_key"], response)
            self.assertEqual(response[case["expected_key"]], case["expected_value"])
        except Exception as e:
            log.error(f"Reset password test failed: {e}")
            self.fail(f"Reset password test failed: {e}")

    def test_login(self):
        """Test logging in with valid credentials and retrieving tokens."""
        try:
            case = self.test_data["login"][0]
            response = self.api.login(email=case["email"], password=case["password"])
            self.assertIsInstance(response, dict)
            self.assertIn("data", response)

            TestManagementUserAuth.access_token = response["data"]["access_token"]
            TestManagementUserAuth.refresh_token = response["data"]["refresh_token"]

            self.assertTrue(self.access_token)
            self.assertTrue(self.refresh_token)
        except Exception as e:
            log.error(f"Login test failed: {e}")
            self.fail(f"Login test failed: {e}")

    def test_refresh_token(self):
        """Test refreshing access token using the refresh token."""
        try:
            self.assertIsNotNone(self.refresh_token, "Refresh token is missing from login step.")
            response = self.api.refresh_token(refresh_token=self.refresh_token)
            self.assertIsInstance(response, dict)
            self.assertIn("data", response)
            self.assertIn("access_token", response["data"])
        except Exception as e:
            log.error(f"Refresh token test failed: {e}")
            self.fail(f"Refresh token test failed: {e}")

    def test_get_current_user(self):
        """Test retrieving the currently logged-in user's details."""
        try:
            self.assertIsNotNone(self.access_token)
            response = self.api.get_current_user(token=self.access_token)
            self.assertIsInstance(response, dict)
            self.assertIn("data", response)
            self.assertEqual(response["data"]["email"], self.email)
            TestManagementUserAuth.user_id = response["data"]["user_id"]
        except Exception as e:
            log.error(f"Get current user test failed: {e}")
            self.fail(f"Get current user test failed: {e}")

    def test_get_user_by_id(self):
        """Test fetching a user's details by their user ID."""
        try:
            self.assertIsNotNone(self.user_id)
            response = self.api.get_user_by_id(user_id=self.user_id, token=self.access_token)
            self.assertIsInstance(response, dict)
            self.assertEqual(response["data"]["id"], self.user_id)
        except Exception as e:
            log.error(f"Get user by ID test failed: {e}")
            self.fail(f"Get user by ID test failed: {e}")

    def test_update_user_by_id(self):
        """Test updating a user's profile details by user ID."""
        try:
            update_payload = {"full_name": "Updated User"}
            response = self.api.update_user_by_id(
                user_id=self.user_id,
                token=self.access_token,
                update_payload=update_payload
            )
            self.assertIsInstance(response, dict)
            self.assertEqual(response["data"]["full_name"], update_payload["full_name"])
        except Exception as e:
            log.error(f"Update user test failed: {e}")
            self.fail(f"Update user test failed: {e}")

    def test_delete_user_by_id(self):
        """Test deleting a user by ID (Soft-delete if supported)."""
        try:
            register_case = self.test_data["register_user"][0]
            temp_user_email = register_case["email"]
            temp_user_password = register_case["password"]

            temp_user = ManagementUserCreate(email=temp_user_email, password=temp_user_password)
            register_response = self.api.register_user(temp_user)
            temp_user_id = register_response["data"]["id"]

            status_code = self.api.delete_user_by_id(user_id=temp_user_id, token=self.access_token)
            self.assertEqual(status_code, 200)
        except Exception as e:
            log.error(f"Delete user test failed: {e}")
            self.fail(f"Delete user test failed: {e}")

    def test_list_management_users(self):
        """Test retrieving a list of all management users."""
        try:
            response = self.api.list_management_users(token=self.access_token)
            self.assertIsInstance(response, dict)
            self.assertIn("data", response)
            self.assertIsInstance(response["data"], list)
        except Exception as e:
            log.error(f"List management users test failed: {e}")
            self.fail(f"List management users test failed: {e}")

    def test_logout_user(self):
        """Test logging out the currently authenticated user."""
        try:
            response = self.api.logout_user(token=self.access_token)
            self.assertIsInstance(response, dict)
            self.assertIn("message", response)
        except Exception as e:
            log.error(f"Logout user test failed: {e}")
            self.fail(f"Logout user test failed: {e}")


if __name__ == "__main__":
    unittest.main()
