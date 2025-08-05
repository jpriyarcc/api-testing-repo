import unittest
import os
import json
import logging
from utils.api_helper1 import ManagementUserAPIHandler
from tests.test_management_user import TestManagementUserAuth
from tests.test_management_role import TestManagementRole

log = logging.getLogger(__name__)


class TestManagementUserRoleAssignment(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Set up API handler and reuse access token, user_id, and role_id from other tests.
        """
        cls.api = ManagementUserAPIHandler(base_url="http://localhost:8000")

        # ✅ Reuse access token from TestManagementUserAuth
        if not TestManagementUserAuth.access_token:
            raise ValueError("Access token not set. Run TestManagementUserAuth tests first.")
        cls.access_token = TestManagementUserAuth.access_token

        #  Reuse user_id and role_id
        if not TestManagementUserAuth.user_id:
            raise ValueError("User ID not set. Run TestManagementUserAuth tests first.")
        if not TestManagementRole.role_id:
            raise ValueError("Role ID not set. Run TestManagementRole tests first.")

        cls.user_id = TestManagementUserAuth.user_id
        cls.role_id = TestManagementRole.role_id

        # Load test data
        json_path = os.path.join(os.path.dirname(__file__), '../utils/test_data.json')
        with open(json_path, "r") as file:
            cls.test_data = json.load(file)

    def test_list_user_roles(self):
        """Test listing all user-role assignments."""
        try:
            response = self.api.list_user_roles(token=self.access_token)
            self.assertIsInstance(response, dict)
            self.assertIn("data", response)
            self.assertIsInstance(response["data"], list)
            log.info("User roles listed successfully.")
        except Exception as e:
            self.fail(f"List user roles test failed: {e}")

    def test_assign_user_role(self):
        """Test assigning a role to a user."""
        try:
            payload = {
                "user_id": self.user_id,
                "role_id": self.role_id
            }
            response = self.api.assign_user_role(token=self.access_token, payload=payload)
            self.assertIsInstance(response, dict)
            self.assertIn("data", response)
            self.assertEqual(response["data"]["user_id"], self.user_id)
            self.assertEqual(response["data"]["role_id"], self.role_id)
            log.info(f"Role assigned successfully to user: {self.user_id}")
        except Exception as e:
            self.fail(f"Assign user role test failed: {e}")

    def test_get_user_role_assignment(self):
        """Test fetching a specific user-role assignment."""
        try:
            response = self.api.get_user_role_assignment(
                token=self.access_token,
                user_id=self.user_id,
                role_id=self.role_id
            )
            self.assertIsInstance(response, dict)
            self.assertIn("data", response)
            self.assertEqual(response["data"]["user_id"], self.user_id)
            self.assertEqual(response["data"]["role_id"], self.role_id)
            log.info(f"Fetched user-role assignment successfully for user: {self.user_id}")
        except Exception as e:
            self.fail(f"Get user role assignment test failed: {e}")

    def test_update_user_role_assignment(self):
        """Test updating an existing user-role assignment."""
        try:
            update_data = self.test_data["update_user_role_assignment"][0]["payload"]
            response = self.api.update_user_role_assignment(
                token=self.access_token,
                user_id=self.user_id,
                role_id=self.role_id,
                update_data=update_data
            )
            self.assertIsInstance(response, dict)
            self.assertIn("data", response)
            self.assertEqual(response["data"]["role_id"], self.role_id)
            log.info(f"Updated user-role assignment successfully for user: {self.user_id}")
        except Exception as e:
            self.fail(f"Update user role assignment test failed: {e}")

    def test_delete_user_role_assignment(self):
        """Test deleting a user-role assignment."""
        try:
            status_code = self.api.delete_user_role_assignment(
                token=self.access_token,
                user_id=self.user_id,
                role_id=self.role_id
            )
            self.assertEqual(status_code, 200)
            log.info(f"Deleted user-role assignment successfully for user: {self.user_id}")
        except Exception as e:
            self.fail(f"Delete user role assignment test failed: {e}")


if __name__ == "__main__":
    unittest.main()
