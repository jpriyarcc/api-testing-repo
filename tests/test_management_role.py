import unittest
import os
import json
import logging
from utils.api_helper1 import ManagementUserAPIHandler
from tests.test_management_user import TestManagementUserAuth

log = logging.getLogger(__name__)


class TestManagementRole(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Set up API handler and reuse access token from TestManagementUserAuth.
        """
        cls.api = ManagementUserAPIHandler(base_url="http://localhost:8000")

        #  Reuse access token from TestManagementUserAuth
        if not TestManagementUserAuth.access_token:
            raise ValueError("Access token not set. Run TestManagementUserAuth tests first.")
        cls.access_token = TestManagementUserAuth.access_token

        # Load test data
        json_path = os.path.join(os.path.dirname(__file__), '../utils/test_data.json')
        with open(json_path, "r") as file:
            cls.test_data = json.load(file)

        cls.role_id = None

    def test_list_roles(self):
        """Test listing all management roles."""
        try:
            response = self.api.list_roles(token=self.access_token)
            self.assertIsInstance(response, dict)
            self.assertIn("data", response)
            self.assertIsInstance(response["data"], list)
            log.info("Roles listed successfully.")
        except Exception as e:
            self.fail(f"List roles test failed: {e}")

    def test_create_role(self):
        """Test creating a new management role."""
        try:
            case = self.test_data["create_role"][0]
            response = self.api.create_role(token=self.access_token, role_data=case["role_data"])
            self.assertIsInstance(response, dict)
            self.assertIn("data", response)
            self.assertEqual(response["data"]["name"], case["role_data"]["name"])

            # Store created role_id for later tests
            TestManagementRole.role_id = response["data"]["id"]
            log.info(f"Role created successfully with ID: {self.role_id}")
        except Exception as e:
            self.fail(f"Create role test failed: {e}")

    def test_update_role_by_id(self):
        """Test updating an existing role by ID."""
        try:
            self.assertIsNotNone(self.role_id, "Role ID is missing from create role step.")
            case = self.test_data["update_role"][0]
            response = self.api.update_role_by_id(
                token=self.access_token,
                role_id=self.role_id,
                update_data=case["update_data"]
            )
            self.assertIsInstance(response, dict)
            self.assertEqual(response["data"]["name"], case["update_data"]["name"])
            log.info(f"Role updated successfully: {self.role_id}")
        except Exception as e:
            self.fail(f"Update role test failed: {e}")

    def test_delete_role_by_id(self):
        """Test deleting a role by ID."""
        try:
            self.assertIsNotNone(self.role_id, "Role ID is missing from create role step.")
            status_code = self.api.delete_role_by_id(token=self.access_token, role_id=self.role_id)
            self.assertEqual(status_code, 200)
            log.info(f"Role deleted successfully: {self.role_id}")
        except Exception as e:
            self.fail(f"Delete role test failed: {e}")


if __name__ == "__main__":
    unittest.main()
