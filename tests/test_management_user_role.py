import logging
import pytest

log = logging.getLogger(__name__)


def test_list_user_roles(api, auth_tokens):
    """Test listing all user-role assignments."""
    try:
        token = auth_tokens.access_token
        response = api.list_user_roles(token=token)
        assert hasattr(response, 'data')
        assert isinstance(response.data, list)
        log.info("User roles listed successfully.")
    except Exception as e:
        pytest.fail(f"List user roles test failed: {e}")


def test_assign_user_role(api, auth_tokens, setup_user, setup_role):
    """Test assigning a role to a user."""
    try:
        token = auth_tokens.access_token
        payload = {
            "user_id": setup_user.user_id,
            "role_id": setup_role.role_id
        }
        response = api.assign_user_role(token=token, payload=payload)
        assert hasattr(response, 'data')
        assert response.data.user_id == setup_user.user_id
        assert response.data.role_id == setup_role.role_id
        log.info(f"Role assigned successfully to user: {setup_user.user_id}")
    except Exception as e:
        pytest.fail(f"Assign user role test failed: {e}")


def test_get_user_role_assignment(api, auth_tokens, setup_user, setup_role):
    """Test fetching a specific user-role assignment."""
    try:
        token = auth_tokens.access_token
        response = api.get_user_role_assignment(
            token=token,
            user_id=setup_user.user_id,
            role_id=setup_role.role_id
        )
        assert hasattr(response, 'data')
        assert response.data.user_id == setup_user.user_id
        assert response.data.role_id == setup_role.role_id
        log.info(f"Fetched user-role assignment successfully for user: {setup_user.user_id}")
    except Exception as e:
        pytest.fail(f"Get user role assignment test failed: {e}")


def test_update_user_role_assignment(api, auth_tokens, setup_user, setup_role, test_data):
    """Test updating an existing user-role assignment."""
    try:
        token = auth_tokens.access_token
        update_data = test_data.update_user_role_assignment[0].payload
        response = api.update_user_role_assignment(
            token=token,
            user_id=setup_user.user_id,
            role_id=setup_role.role_id,
            update_data=update_data
        )
        assert hasattr(response, 'data')
        assert response.data.role_id == setup_role.role_id
        log.info(f"Updated user-role assignment successfully for user: {setup_user.user_id}")
    except Exception as e:
        pytest.fail(f"Update user role assignment test failed: {e}")


def test_delete_user_role_assignment(api, auth_tokens, setup_user, setup_role):
    """Test deleting a user-role assignment."""
    try:
        token = auth_tokens.access_token
        status_code = api.delete_user_role_assignment(
            token=token,
            user_id=setup_user.user_id,
            role_id=setup_role.role_id
        )
        assert status_code == 200
        log.info(f"Deleted user-role assignment successfully for user: {setup_user.user_id}")
    except Exception as e:
        pytest.fail(f"Delete user role assignment test failed: {e}")
