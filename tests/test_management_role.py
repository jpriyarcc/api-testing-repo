import logging
import pytest

log = logging.getLogger(__name__)


class TestManagementUserRoleAssignment:

    def test_list_user_roles(self, api, auth_tokens):
        """
        Test retrieving the list of user roles.
        """
        try:
            token = auth_tokens["access_token"]
            response = api.list_user_roles(token=token)
            assert "data" in response
            assert isinstance(response["data"], list)
            log.info("User roles listed successfully.")
        except Exception as e:
            log.error(f"Failed to list user roles: {e}")
            pytest.fail(str(e))

    def test_assign_user_role(self, api, auth_tokens, setup_user, setup_role):
        """
        Test assigning a role to a user.
        """
        try:
            token = auth_tokens["access_token"]
            payload = {
                "user_id": setup_user.user_id,
                "role_id": setup_role
            }
            response = api.assign_user_role(token=token, payload=payload)
            assert "data" in response
            assert response["data"]["user_id"] == payload["user_id"]
            assert response["data"]["role_id"] == payload["role_id"]
            log.info(f"Role assigned successfully to user: {payload['user_id']}")
        except Exception as e:
            log.error(f"Failed to assign user role: {e}")
            pytest.fail(str(e))

    def test_get_user_role_assignment(self, api, auth_tokens, setup_user, setup_role):
        """
        Test retrieving a specific user-role assignment.
        """
        try:
            token = auth_tokens["access_token"]
            response = api.get_user_role_assignment(
                token=token,
                user_id=setup_user.user_id,
                role_id=setup_role
            )
            assert "data" in response
            assert response["data"]["user_id"] == setup_user.user_id
            assert response["data"]["role_id"] == setup_role
            log.info(f"Fetched user-role assignment successfully for user: {setup_user.user_id}")
        except Exception as e:
            log.error(f"Failed to get user-role assignment: {e}")
            pytest.fail(str(e))

    def test_update_user_role_assignment(self, api, auth_tokens, setup_user, setup_role, test_data):
        """
        Test updating a user-role assignment.
        """
        try:
            token = auth_tokens["access_token"]
            update_data = test_data["update_user_role_assignment"][0]["payload"]
            response = api.update_user_role_assignment(
                token=token,
                user_id=setup_user.user_id,
                role_id=setup_role,
                update_data=update_data
            )
            assert "data" in response
            assert response["data"]["role_id"] == setup_role
            log.info(f"Updated user-role assignment successfully for user: {setup_user.user_id}")
        except Exception as e:
            log.error(f"Failed to update user-role assignment: {e}")
            pytest.fail(str(e))

    def test_delete_user_role_assignment(self, api, auth_tokens, setup_user, setup_role):
        """
        Test deleting a user-role assignment.
        """
        try:
            token = auth_tokens["access_token"]
            status_code = api.delete_user_role_assignment(
                token=token,
                user_id=setup_user.user_id,
                role_id=setup_role
            )
            assert status_code == 200
            log.info(f"Deleted user-role assignment successfully for user: {setup_user.user_id}")
        except Exception as e:
            log.error(f"Failed to delete user-role assignment: {e}")
            pytest.fail(str(e))
