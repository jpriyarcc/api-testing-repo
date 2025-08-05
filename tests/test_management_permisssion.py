import pytest
import logging

log = logging.getLogger(__name__)


permission_group_id = None


def test_list_permission_groups(api, auth_tokens):
    """Test listing all permission groups."""
    try:
        token = auth_tokens.access_token
        response = api.list_permission_groups(token=token)
        assert hasattr(response, "data")
        assert isinstance(response.data, list)
        log.info("Permission groups listed successfully.")
    except Exception as e:
        pytest.fail(f"List permission groups test failed: {e}")


def test_create_permission_group(api, auth_tokens, test_data):
    """Test creating a new permission group."""
    global permission_group_id
    try:
        token = auth_tokens.access_token
        case = test_data["create_permission_group"][0]
        payload = case["payload"]
        response = api.create_permission_group(token=token, payload=payload)

        assert hasattr(response, "data")
        assert response.data.name == payload["name"]

        # Store created permission group ID globally
        permission_group_id = response.data.id
        log.info(f"Permission group created successfully with ID: {permission_group_id}")
    except Exception as e:
        pytest.fail(f"Create permission group test failed: {e}")


def test_update_permission_group(api, auth_tokens, test_data):
    """Test updating a permission group by ID."""
    global permission_group_id
    try:
        token = auth_tokens.access_token
        assert permission_group_id is not None, "Permission group ID is missing"

        update_payload = test_data["update_permission_group"][0]["payload"]
        response = api.update_permission_group(token=token, group_id=permission_group_id, payload=update_payload)

        assert hasattr(response, "data")
        assert response.data.name == update_payload["name"]
        log.info(f"Permission group updated successfully: {permission_group_id}")
    except Exception as e:
        pytest.fail(f"Update permission group test failed: {e}")


def test_delete_permission_group(api, auth_tokens):
    """Test deleting a permission group by ID."""
    global permission_group_id
    try:
        token = auth_tokens.access_token
        assert permission_group_id is not None, "Permission group ID is missing"

        status_code = api.delete_permission_group(token=token, group_id=permission_group_id)
        assert status_code == 200
        log.info(f"Permission group deleted successfully: {permission_group_id}")
    except Exception as e:
        pytest.fail(f"Delete permission group test failed: {e}")


def test_update_management_permission_group(api, auth_tokens, test_data):
    """Test alternate update method for permission group."""
    try:
        token = auth_tokens.access_token
        payload = test_data["create_permission_group"][0]["payload"]
        create_resp = api.create_permission_group(token=token, payload=payload)
        group_id = create_resp.data.id

        update_data = test_data["update_permission_group"][0]["payload"]
        update_resp = api.update_management_permission_group(
            token=token,
            group_id=group_id,
            update_data=update_data
        )

        assert hasattr(update_resp, "data")
        assert update_resp.data.name == update_data["name"]
        log.info(f"Management permission group updated successfully: {group_id}")
    except Exception as e:
        pytest.fail(f"Update management permission group test failed: {e}")


def test_delete_management_permission_group(api, auth_tokens, test_data):
    """Test alternate delete method for permission group."""
    try:
        token = auth_tokens.access_token
        payload = test_data["create_permission_group"][0]["payload"]
        create_resp = api.create_permission_group(token=token, payload=payload)
        group_id = create_resp.data.id

        status_code = api.delete_management_permission_group(token=token, group_id=group_id)
        assert status_code == 200
        log.info(f"Management permission group deleted successfully: {group_id}")
    except Exception as e:
        pytest.fail(f"Delete management permission group test failed: {e}")
