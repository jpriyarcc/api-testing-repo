import pytest
import logging

log = logging.getLogger(__name__)


log_id = None


def test_list_audit_logs(api, auth_tokens):
    """
    Test fetching a paginated list of audit logs.
    """
    global log_id
    try:
        token = auth_tokens.access_token
        response = api.list_audit_logs(token=token)

        assert hasattr(response, "data")
        assert isinstance(response.data, list)

        if response.data:
            log_id = response.data[0].id

        log.info("Audit logs listed successfully.")
    except Exception as e:
        pytest.fail(f"List audit logs test failed: {e}")


def test_get_audit_log_by_id(api, auth_tokens):
    """
    Test retrieving a single audit log by its ID.
    """
    if not log_id:
        pytest.skip("No audit log available to fetch by ID.")

    try:
        token = auth_tokens.access_token
        response = api.get_audit_log_by_id(token=token, log_id=log_id)

        assert hasattr(response, "data")
        assert response.data.id == log_id
        log.info(f"Fetched audit log successfully with ID: {log_id}")
    except Exception as e:
        pytest.fail(f"Get audit log by ID test failed: {e}")
