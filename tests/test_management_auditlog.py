import unittest
import logging
from utils.api_helper1 import ManagementUserAPIHandler
from tests.test_management_user import TestManagementUserAuth  # Reuse access token

log = logging.getLogger(__name__)


class TestManagementAuditLog(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Set up API handler and reuse access token from TestManagementUserAuth.
        """
        cls.api = ManagementUserAPIHandler(base_url="http://localhost:8000")

        # Ensure access token is available
        if not TestManagementUserAuth.access_token:
            raise ValueError("Access token not set. Run TestManagementUserAuth tests first.")
        cls.access_token = TestManagementUserAuth.access_token

        cls.log_id = None  # Will be fetched dynamically

    def test_list_audit_logs(self):
        """Test fetching a paginated list of audit logs."""
        try:
            response = self.api.list_audit_logs(token=self.access_token)
            self.assertIsInstance(response, dict)
            self.assertIn("data", response)
            self.assertIsInstance(response["data"], list)

            # Store first audit log ID for later test (if available)
            if response["data"]:
                TestManagementAuditLog.log_id = response["data"][0]["id"]

            log.info("Audit logs listed successfully.")
        except Exception as e:
            self.fail(f"List audit logs test failed: {e}")

    def test_get_audit_log_by_id(self):
        """Test retrieving a single audit log by its ID."""
        if not self.log_id:
            self.skipTest("No audit log available to fetch by ID.")

        try:
            response = self.api.get_audit_log_by_id(token=self.access_token, log_id=self.log_id)
            self.assertIsInstance(response, dict)
            self.assertIn("data", response)
            self.assertEqual(response["data"]["id"], self.log_id)
            log.info(f"Fetched audit log successfully with ID: {self.log_id}")
        except Exception as e:
            self.fail(f"Get audit log by ID test failed: {e}")


if __name__ == "__main__":
    unittest.main()
