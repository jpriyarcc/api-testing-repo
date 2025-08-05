import unittest
import os
import json
import logging
from utils.api_helper1 import ManagementUserAPIHandler
from tests.test_management_user import TestManagementUserAuth

log = logging.getLogger(__name__)


class TestManagementPermissionGroup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Set up API handler and reuse access token from TestManagementUserAuth.
        """
        cls.api = ManagementUserAPIHandler(base_url="http://localhost:8000")

        # Reuse access token from TestManagementUserAuth
        if not TestManagementUserAuth.access_token:
            raise ValueError("Access token not set. Run TestManagementUserAuth tests first.")
        cls.access_token = TestManagementUserAuth.access_token

        # Load test data
        json_path = os.path.join(os.path.dirname(__file__), '../utils/test_data.json')
        with open(json_path, "r") as file:
            cls.test_data = json.load(file)

        cls.permission_group_id = None

    def test_list_permission_groups(self):
        """Test listing all permission groups."""
        try:
            response = self.api.list_permission_groups(token=self.access_token)
            self.assertIsInstance(response, dict)
            self.assertIn("data", response)
            self.assertIsInstance(response["data"], list)
            log.info("Permission groups listed successfully.")
        except Exception as e:
            self.fail(f"List permission groups test failed: {e}")

    def test_create_permission_group(self):
        """Test creating a new permission group."""
        try:
            case = self.test_data["create_permission_group"][0]
            response = self.api.create_permission_group(token=self.access_token, payload=case["payload"])
            self.assertIsInstance(response, dict)
            self.assertIn("data", response)
            self.assertEqual(response["data"]["name"], case["payload"]["name"])

            # Store created permission group ID
            TestManagementPermissionGroup.permission_group_id = response["data"]["id"]
            log.info(f"Permission group created successfully with ID: {self.permission_group_id}")
        except Exception as e:
            self.fail(f"Create permission group test failed: {e}")

    def test_update_permission_group(self):
        """Test updating a permission group by ID."""
        try:
            self.assertIsNotNone(self.permission_group_id, "Permission group ID is missing from create step.")
            case = self.test_data["update_permission_group"][0]
            response = self.api.update_permission_group(
                token=self.access_token,
                group_id=self.permission_group_id,
                payload=case["payload"]
            )
            self.assertIsInstance(response, dict)
            self.assertEqual(response["data"]["name"], case["payload"]["name"])
            log.info(f"Permission group updated successfully: {self.permission_group_id}")
        except Exception as e:
            self.fail(f"Update permission group test failed: {e}")

    def test_delete_permission_group(self):
        """Test deleting a permission group by ID."""
        try:
            self.assertIsNotNone(self.permission_group_id, "Permission group ID is missing from create step.")
            status_code = self.api.delete_permission_group(token=self.access_token, group_id=self.permission_group_id)
            self.assertEqual(status_code, 200)
            log.info(f"Permission group deleted successfully: {self.permission_group_id}")
        except Exception as e:
            self.fail(f"Delete permission group test failed: {e}")

    def test_update_management_permission_group(self):
        """Test updating a permission group using the alternate update method."""
        try:
            # Re-create a permission group for this update test
            case_create = self.test_data["create_permission_group"][0]
            response_create = self.api.create_permission_group(token=self.access_token, payload=case_create["payload"])
            group_id = response_create["data"]["id"]

            case_update = self.test_data["update_permission_group"][0]
            response_update = self.api.update_management_permission_group(
                token=self.access_token,
                group_id=group_id,
                update_data=case_update["payload"]
            )
            self.assertIsInstance(response_update, dict)
            self.assertEqual(response_update["data"]["name"], case_update["payload"]["name"])
            log.info(f"Management permission group updated successfully: {group_id}")
        except Exception as e:
            self.fail(f"Update management permission group test failed: {e}")

    def test_delete_management_permission_group(self):
        """Test deleting a permission group using the alternate delete method."""
        try:
            # Re-create a permission group for deletion test
            case_create = self.test_data["create_permission_group"][0]
            response_create = self.api.create_permission_group(token=self.access_token, payload=case_create["payload"])
            group_id = response_create["data"]["id"]

            status_code = self.api.delete_management_permission_group(token=self.access_token, group_id=group_id)
            self.assertEqual(status_code, 200)
            log.info(f"Management permission group deleted successfully: {group_id}")
        except Exception as e:
            self.fail(f"Delete management permission group test failed: {e}")


if __name__ == "__main__":
    unittest.main()
