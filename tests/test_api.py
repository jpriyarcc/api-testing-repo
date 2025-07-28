"""
Management user API
"""

import json

import os

from utils.api_data import ManagementUserCreate
from utils.api_helper import ManagementUserAPIHandler
import pytest

import logging

log = logging.getLogger(__name__)

api = ManagementUserAPIHandler(base_url="http://localhost:8000/")
json_path = os.path.join(os.path.dirname(__file__), '../utils/test_data.json')
with open(json_path, 'r') as f:
    test_data = json.load(f)


def get_case_by_index(section, index=0):
    data_list = test_data.get(section, [])
    return [data_list[index]] if len(data_list) > index else []


def get_test_cases(section):
    """
    Retrieve test cases for a given section from the loaded JSON data.
    """
    return test_data.get(section, [])


@pytest.mark.parametrize("case", get_case_by_index("register_user", index=0))
def test_register_user_variants(case):
    """
    Test the registration of users with different input variants.
    """
    try:
        user = ManagementUserCreate(email=case["email"], password=case["password"])
        response = api.register_user(user)
        assert response.status_code == case["expected_status"]

        data = response.json()
        if case["expected_status"] == 201:
            assert data["data"]["email"] == case["email"]
        elif case["expected_status"] == 409:
            assert data.get("error_code") == case["expected_error_code"]
        elif case["expected_status"] == 422:
            assert "detail" in data

    except Exception as e:
        log.error(f"Error in test_register_user_variants: {e}")
        raise


@pytest.mark.parametrize("case", get_case_by_index("verify_email", index=0))
def test_verify_email(case):
    """
    Test the email verification process using provided token.
    """
    try:
        resp = api.verify_email(case["token"])
        assert resp.status_code == case["expected_status"]

        if case["expected_status"] in (200, 400, 404):
            data = resp.json()
            if case["expected_status"] == 200:
                assert "verified" in data.get("message", "").lower()
            else:
                assert data.get(case["expected_key"]) == case["expected_value"]

    except Exception as e:
        log.error(f"Error in test_verify_email: {e}")
        raise


@pytest.mark.parametrize("case", get_case_by_index("resend_verification", index=0))
def test_resend_verification(case):
    """
    Test the resend verification API using email variants.
    """
    try:
        resp = api.resend_verification(case["email"])
        assert resp.status_code == case["expected_status"]

        if case["expected_key"]:
            data = resp.json()
            assert data.get(case["expected_key"]) == case["expected_value"]

    except Exception as e:
        log.error(f"Error in test_resend_verification: {e}")
        raise


@pytest.mark.parametrize("case", get_case_by_index("forgot_password", index=0))
def test_forgot_password(case):
    """
    Test the forgot password functionality using different email inputs.
    """
    try:
        resp = api.forgot_password(case["email"])
        assert resp.status_code == case["expected_status"]

        data = resp.json()
        if case["expected_status"] == 200:
            assert data.get("message") == case["expected_value"]
        elif case["expected_status"] == 404:
            assert data.get("error_code") == case["expected_value"]
        elif case["expected_status"] == 422:
            assert "detail" in data

    except Exception as e:
        log.error(f"Error in test_forgot_password: {e}")
        raise


@pytest.mark.parametrize("case", get_case_by_index("reset_password", index=0))
def test_reset_password(case):
    """
    Test the password reset functionality with different token and password inputs.
    """
    try:
        resp = api.reset_password(case["token"], case["password"], case["cpassword"])
        assert resp.status_code == case["expected_status"]

        data = resp.json()
        if case["expected_status"] == 200:
            assert data.get("success") is True
        elif case["expected_status"] == 400:
            assert data.get("error_code") == case["expected_value"]
        elif case["expected_status"] == 422:
            assert "detail" in data

    except Exception as e:
        log.error(f"Error in test_reset_password: {e}")
        raise


global_access_token = ""
global_refresh_token = ""


@pytest.mark.sanity
@pytest.mark.dependency(name="login")
@pytest.mark.parametrize("case", get_case_by_index("login", index=0))
def test_login_user(case):
    """
    Logs in a user and sets global access and refresh tokens.
    """
    global global_access_token, global_refresh_token

    try:
        resp = api.login(email=case["email"], password=case["password"])
        assert resp.status_code == case["expected_status"], f"Login failed: {resp.text}"
        data = resp.json().get("data", {})
        global_access_token = data.get("access_token")
        global_refresh_token = data.get("refresh_token")

        assert global_access_token, "Missing access_token"
        assert global_refresh_token, "Missing refresh_token"

    except Exception as e:
        pytest.fail(f"Login test failed: {e}")


@pytest.mark.regression
@pytest.mark.dependency(depends=["login"])
def test_refresh_token():
    """
    Refreshes access token using the global refresh token.
    """
    global global_refresh_token

    try:
        assert global_refresh_token, "Refresh token not set. Run login test first."

        case = get_case_by_index("refresh_token", 0)[0]
        resp = api.refresh_token(global_refresh_token)
        assert resp.status_code == case["expected_status"], f"Refresh failed: {resp.text}"

        new_access_token = resp.json().get("access_token")
        assert new_access_token, "No new access token returned"

    except Exception as e:
        pytest.fail(f"Refresh token test failed: {e}")


@pytest.mark.dependency(depends=["login"])
def test_logout_user():
    global global_access_token
    try:
        assert global_access_token, "Access token is not set. Run login test first."

        response = api.logout_user(global_access_token)
        assert response.status_code == 200, f"Unexpected status code: {response.status_code}"

        json_data = response.json()
        assert "message" in json_data, "Response missing 'message'"
        assert "status" in json_data, "Response missing 'status'"
        assert json_data["status"] == 200, f"Expected status 200, got {json_data['status']}"

    except AssertionError as ae:
        print(f"AssertionError: {ae}")
        raise
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        raise


global_user_id = ""


@pytest.mark.dependency(depends=["login"])
def test_get_current_user():
    """
    Test to verify retrieval of the current user using the access token.
    Sets global_user_id from the response.

    Raises:
        AssertionError: If any assertion fails.
        Exception: If any unexpected error occurs.
    """
    global global_access_token, global_user_id

    try:
        # Ensure the access token is available
        assert global_access_token, "Access token is not set. Run login test first."

        response = api.get_current_user(global_access_token)
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}"

        json_data = response.json()

        # Basic response structure validation
        assert "status" in json_data, "'status' missing in response"
        assert "message" in json_data, "'message' missing in response"
        assert "data" in json_data, "'data' missing in response"

        user_data = json_data["data"]

        # Validate required user fields
        assert "email" in user_data, "'email' missing in user data"
        assert "id" in user_data, "'id' missing in user data"

        global_user_id = user_data["id"]
        log.info(f"User ID: {global_user_id}")

    except AssertionError as ae:
        log.error(f"AssertionError in test_get_current_user: {ae}")
        raise
    except Exception as e:
        log.error(f"Unexpected error in test_get_current_user: {e}")
        raise


@pytest.mark.dependency(depends=["login"])
def test_get_management_user_by_id():
    """
    Test fetching a management user by ID and validate that the response is correct.
    Assumes global_user_id and global_access_token are already set from previous tests.
    """
    global global_user_id, global_access_token

    try:
        # Ensure required global values are set
        assert global_user_id, "User ID not set. Run test_get_current_user first."
        assert global_access_token, "Access token not set. Run login test first."

        response = api.get_user_by_id(global_user_id, global_access_token)
        status_code = response.status_code

        # Validate HTTP status code
        assert status_code == 200, f"Expected 200 OK, got {status_code}"

        json_data = response.json()

        assert "status" in json_data, "'status' missing in response"
        assert "message" in json_data, "'message' missing in response"
        assert "data" in json_data, "'data' missing in response"
        assert isinstance(json_data["data"], dict), "'data' is not a dictionary"

        log.info("test_get_management_user_by_id passed successfully.")

    except AssertionError as ae:
        log.error(f"Assertion failed: {ae}")
        raise
    except Exception as e:
        log.error(f"Unexpected error occurred: {e}")
        raise


@pytest.mark.dependency(depends=["login"])
@pytest.mark.parametrize("case", get_case_by_index("update_management_user", index=0))
def test_update_management_user_by_id(case):
    """
    Test updating a management user using a single case from JSON.
    """
    global global_user_id, global_access_token

    try:
        payload = case["payload"]
        expected_status = case["expected_status"]

        assert global_user_id, "User ID not set. Run test_get_current_user first."
        assert global_access_token, "Token not set. Run login test first."

        response = api.update_user_by_id(global_user_id, global_access_token, payload)
        status_code = response.status_code

        assert status_code == expected_status, f"Expected {expected_status}, got {status_code}"
        json_data = response.json()
        data = json_data.get("data", {})

        if expected_status == 200:
            assert isinstance(data, dict), "'data' should be a dictionary"
            for key, val in payload.items():
                assert data.get(key) == val, f"Mismatch in field '{key}'"

        elif expected_status == 422:
            assert "detail" in json_data, "'detail' key missing for 422 validation error"
            assert isinstance(json_data["detail"], list), "'detail' should be a list"

        elif expected_status == 401:
            assert json_data.get("error_code") in ["E401", "E403", "Unauthorized"]
            message = json_data.get("message", "").lower()
            assert "unauthorized" in message or "token" in message

        log.info(f"Update test passed with payload: {payload}")

    except AssertionError as ae:
        log.error(f"Assertion failed: {ae}")
        raise
    except Exception as e:
        log.error(f"Unexpected error: {e}")
        raise


@pytest.mark.dependency(depends=["login"])
def test_delete_management_user_by_id():
    """
    Test to delete a management user by ID with proper error handling.
    """
    global global_user_id, global_access_token

    try:
        assert global_user_id, "User ID not set. Run test_get_current_user first."
        assert global_access_token, "Token not set. Run login test first."

        response = api.delete_user_by_id(global_user_id, global_access_token)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"

        json_data = response.json()
        assert "status" in json_data, "Missing 'status' in response"
        assert "message" in json_data, "Missing 'message' in response"
        assert json_data["status"] == 200, f"Expected status 200, got {json_data['status']}"

    except AssertionError as e:
        log.error(f"Validation failed: {e}")
        raise
    except Exception as e:
        log.exception("Unexpected error occurred during user deletion:")
        raise


@pytest.mark.parametrize("case", get_test_cases("list_management_users"))
def test_list_management_users(case):
    """
    Test listing management users with various parameters.
    """
    global global_access_token
    assert global_access_token, "Token not set. Run login test first."

    try:
        response = api.list_management_users(token=global_access_token, params=case["params"])
        assert response.status_code == case[
            "expected_status"], f"Expected {case['expected_status']}, got {response.status_code}"

        json_data = response.json()

        if case["expected_status"] == 200:
            assert "status" in json_data
            assert "message" in json_data
            assert "data" in json_data
            assert isinstance(json_data["data"], list)
            assert "total" in json_data
            assert "page" in json_data
            assert "page_size" in json_data
            assert "total_pages" in json_data
        else:
            assert "error_code" in json_data
            assert "message" in json_data

    except KeyError as e:
        log.error(f"Missing expected key: {e}")
        pytest.fail(f"Missing expected key: {e}")
    except AssertionError as e:
        log.error(f"Assertion failed: {e}")
        pytest.fail(f"Assertion failed: {e}")
    except Exception as e:
        log.error(f"Unexpected error: {e}")
        pytest.fail(f"Unexpected error: {e}")


global_role_id = ""


@pytest.mark.parametrize("test_case", get_test_cases("test_create_management_role"))
def test_create_management_role(test_case):
    """
    Test creating a new management role using data from JSON file.
    Save the role ID globally if creation is successful.
    """
    global global_access_token, global_role_id
    assert global_access_token, "Token not set. Run login test first."

    role_data = test_case["role_data"]
    expected_status = test_case["expected_status"]

    try:
        response = api.create_role(token=global_access_token, role_data=role_data)
        log.info(f"Status Code: {response.status_code}")
        assert response.status_code == expected_status, f"Expected {expected_status}, got {response.status_code}"

        json_data = response.json()
        if expected_status in [200, 201]:
            assert "status" in json_data
            assert "message" in json_data
            assert "data" in json_data
            assert isinstance(json_data["data"], dict)

            global_role_id = json_data["data"].get("id")
            log.info(f"Role created successfully. Role ID: {global_role_id}")

        elif expected_status == 422:
            assert "detail" in json_data or "Validation" in json_data.get("message", "")
            log.info("Validation error as expected.")

    except Exception as e:
        log.error(f"Exception during role creation: {e}", exc_info=True)
        pytest.fail(f"Test failed due to exception: {e}")


def test_get_management_role_by_id():
    """
    Test retrieving a management role by ID using global values.
    """
    global global_access_token, global_role_id
    assert global_access_token, "Token not set. Run login test first."
    assert global_role_id, "Role ID not set. Run role creation test first."

    try:
        response = api.get_role_by_id(token=global_access_token, role_id=global_role_id)
        log.info(f"Status Code: {response.status_code}")

        if response.status_code == 200:
            json_data = response.json()
            assert "status" in json_data
            assert "message" in json_data
            assert "data" in json_data
            assert isinstance(json_data["data"], dict)
            log.info(f"Role fetched successfully. Role ID: {global_role_id}")

        elif response.status_code == 404:
            json_data = response.json()
            assert json_data.get("error_code") == "E404"
            assert json_data.get("message") == "Role not found"
            log.warning("Role not found.")

        else:
            pytest.fail(f"Unexpected status code: {response.status_code}")

    except Exception as e:
        log.error(f"Exception during role retrieval: {e}", exc_info=True)
        pytest.fail(f"Test failed due to exception: {e}")


@pytest.mark.parametrize("test_case", get_test_cases("test_update_and_delete_management_role"))
def test_update_and_delete_management_role(test_case):
    """
    Test updating and deleting a management role using global role ID and JSON data.
    """
    global global_access_token, global_role_id
    assert global_access_token, "Token not set. Run login test first."
    assert global_role_id, "Role ID not set. Run role creation test first."

    update_payload = test_case["update_payload"]
    expected_status = test_case["expected_status"]

    try:
        # Update the role
        update_response = api.update_role_by_id(
            token=global_access_token,
            role_id=global_role_id,
            update_data=update_payload
        )
        log.info(f"Update status code: {update_response.status_code}")
        assert update_response.status_code == expected_status, f"Expected {expected_status}, got {update_response.status_code}"

        json_data = update_response.json()

        if expected_status == 200:
            assert "status" in json_data
            assert "message" in json_data
            assert "data" in json_data
            assert isinstance(json_data["data"], dict)
            assert json_data["data"]["name"] == update_payload["name"]
            assert json_data["data"]["description"] == update_payload["description"]
            log.info("Role updated successfully.")

            delete_response = api.delete_role_by_id(
                token=global_access_token,
                role_id=global_role_id
            )
            log.info(f"Delete status code: {delete_response.status_code}")
            assert delete_response.status_code == 204, f"Expected 204 on delete, got {delete_response.status_code}"
            log.info("Role deleted successfully.")

        elif expected_status == 404:
            assert json_data.get("error_code") == "E404"
            assert json_data.get("message") == "Role not found"
            log.warning("Role not found during update.")

        elif expected_status == 422:
            assert "detail" in json_data or "Validation" in json_data.get("message", "")
            log.warning("Validation failed as expected.")

    except Exception as e:
        log.error(f"Exception during update/delete role: {e}", exc_info=True)
        pytest.fail(f"Test failed due to exception: {e}")


@pytest.mark.parametrize("test_case", get_test_cases("test_list_roles"))
def test_list_roles(test_case):
    """
    Test listing roles with different page and page_size combinations using global token and JSON data.
    """
    global global_access_token
    assert global_access_token, "Token not set. Run login test first."

    page = test_case["page"]
    page_size = test_case["page_size"]
    expected_status = test_case["expected_status"]

    try:
        response = api.list_roles(
            token=global_access_token,
            page=page,
            page_size=page_size
        )
        log.info(f"Status Code: {response.status_code}")
        assert response.status_code == expected_status, f"Expected {expected_status}, got {response.status_code}"

        json_data = response.json()

        if expected_status == 200:
            assert "status" in json_data
            assert "message" in json_data
            assert "data" in json_data and isinstance(json_data["data"], list)
            assert "page" in json_data
            assert "page_size" in json_data
            assert "total" in json_data
            assert "total_pages" in json_data
            log.info("Role listing validated successfully.")

        elif expected_status == 422:
            assert json_data.get("error_code") == "E422"
            assert "Invalid" in json_data.get("message", "")
            log.info("Validation error as expected.")

    except Exception as e:
        log.error(f"Exception during role listing: {e}", exc_info=True)
        pytest.fail(f"Test failed due to exception: {e}")


valid_token = global_access_token


@pytest.mark.parametrize("test_case", get_test_cases("test_assign_permission_to_role"))
def test_assign_permission_to_role(test_case):
    """
        Test assigning a permission to a role.

        Args:
            test_case (dict): Test case data with payload and expected status.
        """

    payload = test_case["payload"]
    expected_status = test_case["expected_status"]

    try:
        response = api.assign_permission_to_role(
            token=valid_token,
            payload=payload
        )

        assert response is not None, "API response is None"
        assert response.status_code == expected_status, f"Expected {expected_status}, got {response.status_code}"

        json_data = response.json()

        if expected_status == 201:
            assert "status" in json_data, "'status' key missing in response"
            assert "message" in json_data, "'message' key missing in response"
            assert "data" in json_data, "'data' key missing in response"
            assert isinstance(json_data["data"], dict), "'data' should be a dictionary"
            assert json_data["data"].get("role_id") == payload["role_id"], "Role ID mismatch"
            assert json_data["data"].get("permission_id") == payload["permission_id"], "Permission ID mismatch"

        elif expected_status == 422:
            assert "message" in json_data, "'message' key should be present for validation error"

    except Exception as e:
        pytest.fail(f"Test failed due to unexpected exception: {e}")


@pytest.mark.parametrize("test_case", get_test_cases("test_role_permission_get_update_delete_flow"))
def test_role_permission_get_update_delete_flow(test_case):
    """
        Test the full lifecycle of role-permission mapping:

        """
    role_id = test_case["role_id"]
    permission_id = test_case["permission_id"]

    try:
        # 1. GET before update
        get_resp = api.get_role_permission(valid_token, role_id, permission_id)
        assert get_resp.status_code in (200, 404), f"Unexpected GET status: {get_resp.status_code}"

        if get_resp.status_code == 404:
            pytest.skip("Role-permission mapping not found before update.")

        json_data = get_resp.json()
        assert "data" in json_data, "'data' missing in GET response"

        # 2. PUT — update assignment
        update_payload = {
            "role_id": role_id,
            "permission_id": permission_id
        }

        put_resp = api.update_role_permission(valid_token, role_id, permission_id, update_payload)
        assert put_resp.status_code == 200, f"Update failed: {put_resp.status_code} {put_resp.text}"

        put_data = put_resp.json()
        assert put_data["status"] == 200
        assert put_data["data"]["role_id"] == role_id
        assert put_data["data"]["permission_id"] == permission_id

        # 3. GET after update
        get_after_put = api.get_role_permission(valid_token, role_id, permission_id)
        assert get_after_put.status_code == 200, f"GET after update failed: {get_after_put.status_code}"
        after_data = get_after_put.json()["data"]
        assert after_data["role_id"] == role_id
        assert after_data["permission_id"] == permission_id

        # 4. DELETE the assignment
        delete_resp = api.delete_role_permission(valid_token, role_id, permission_id)
        assert delete_resp.status_code == 204, f"Delete failed: {delete_resp.status_code} {delete_resp.text}"

        # 5. GET after delete
        get_after_delete = api.get_role_permission(valid_token, role_id, permission_id)
        assert get_after_delete.status_code == 404, "Expected 404 after delete"

    except Exception as e:
        pytest.fail(f"Test failed due to exception: {e}")


@pytest.mark.parametrize("test_case", get_test_cases("test_list_role_permissions"))
def test_list_role_permissions(test_case):
    """
        Test listing role-permission mappings with pagination.

        Args:
            test_case (dict): Includes page, page_size, and expected_status.
        """
    page = test_case["page"]
    page_size = test_case["page_size"]
    expected_status = test_case.get("expected_status", 200)

    try:
        response = api.list_role_permissions(
            token=valid_token,
            page=page,
            page_size=page_size
        )

        assert response.status_code == expected_status, f"Expected {expected_status}, got {response.status_code}"

        if expected_status == 200:
            json_data = response.json()

            assert json_data.get("status") == 200, "Incorrect status in response"
            assert "message" in json_data
            assert "data" in json_data

            # Pagination checks
            assert "page" in json_data
            assert "page_size" in json_data
            assert "total" in json_data
            assert "total_pages" in json_data

            # Validate actual page data
            assert json_data["page"] == page
            assert json_data["page_size"] == page_size
            assert isinstance(json_data["data"], (list, dict))

    except Exception as e:
        pytest.fail(f"Test failed due to exception: {e}")


@pytest.mark.parametrize("test_case", get_test_cases("test_create_management_permission"))
def test_create_management_permission(test_case):
    """
        Test creating a management permission.

        Args:
            test_case (dict): Includes permission data and expected status.
        """
    permission_data = test_case["permission_data"]
    expected_status = test_case["expected_status"]

    try:
        response = api.create_management_permission(valid_token, permission_data)

        log.info(f"\n Request URL: {response.request.url}")
        log.info("Request Body:", permission_data)
        log.info("Status Code:", response.status_code)
        log.info("Response Body:", response.text)

        assert response.status_code == expected_status, (
            f"Expected {expected_status}, got {response.status_code}"
        )

        json_data = response.json()

        if expected_status == 201:
            assert json_data.get("status") == 201, "Expected status key to be 201"
            assert "message" in json_data, "Missing 'message' in response"
            assert "data" in json_data, "Missing 'data' in response"
            assert "name" in json_data["data"], "Missing 'name' in response data"

        elif expected_status == 422:
            assert "detail" in json_data, "Expected 'detail' in response for validation error"

    except Exception as e:
        pytest.fail(f"Test failed due to exception: {str(e)}")


@pytest.mark.parametrize("test_case", get_test_cases("test_get_permission_by_id"))
def test_get_permission_by_id(test_case):
    """
        Test retrieving a management permission by ID.

        Args:
            test_case (dict): Includes permission_id and expected_status.
        """
    permission_id = test_case["permission_id"]
    expected_status = test_case["expected_status"]

    try:
        response = api.get_management_permission_by_id(valid_token, permission_id)

        log.info(f"Request URL: {response.request.url}")
        log.info(f"Status Code: {response.status_code}")
        log.info(f"Response Body: {response.text}")

        assert response.status_code == expected_status, f"Expected {expected_status}, got {response.status_code}"

        json_data = response.json()

        if expected_status == 200:
            assert json_data.get("status") == 200, "Expected status 200 in response"
            assert "data" in json_data, "Missing 'data' in response"
            assert "name" in json_data["data"], "Missing 'name' field"
            log.info("Permission name: %s", json_data["data"]["name"])

        elif expected_status == 404:
            assert json_data.get("error_code") == "E404", "Expected error_code 'E404'"
            assert "not found" in json_data.get("message", "").lower()
            log.info("Error message: %s", json_data["message"])

        elif expected_status == 422:
            assert "detail" in json_data, "Expected validation details in response"
            log.info("Validation error: %s", json_data["detail"])

    except Exception as e:
        pytest.fail(f"Test failed due to exception: {str(e)}")


@pytest.mark.parametrize("test_case", get_test_cases("test_update_permission_by_id"))
def test_update_permission_by_id(test_case):
    """
    Test updating management permission by ID with valid and invalid inputs.
    """
    permission_id = test_case["permission_id"]
    update_data = test_case["update_data"]
    expected_status = test_case["expected_status"]

    try:
        response = api.update_permission(valid_token, permission_id, update_data)

        log.info(f"Request URL: {response.request.url}")
        log.info(f"Status Code: {response.status_code}")
        log.info(f"Response Body: {response.text}")

        assert response.status_code == expected_status, f"Expected {expected_status}, got {response.status_code}"

        json_data = response.json()

        if expected_status == 200:
            assert json_data.get("status") == 200, "Expected status code 200 in response"
            assert "data" in json_data, "Missing 'data' field"
            assert json_data["data"].get("code") == update_data["code"], "Code mismatch"
            log.info("Updated Permission Code: %s", json_data["data"]["code"])

        elif expected_status == 404:
            assert json_data.get("error_code") == "E404", "Expected error_code 'E404'"
            assert "not found" in json_data.get("message", "").lower()
            log.info("Error: %s", json_data.get("message"))

        elif expected_status == 422:
            assert "detail" in json_data, "Expected validation error details"
            log.info("Validation error: %s", json_data["detail"])

    except Exception as e:
        pytest.fail(f"Test failed due to exception: {str(e)}")


@pytest.mark.parametrize("test_case", get_test_cases("test_delete_permission_by_id"))
def test_delete_permission_by_id(test_case):
    """
    Test deleting management permission by ID with valid and invalid inputs.
    """
    permission_id = test_case["permission_id"]
    token = test_case["token"]
    expected_status = test_case["expected_status"]

    try:
        response = api.delete_permission(token, permission_id)

        log.info(f"Request URL: {response.request.url}")
        log.info(f"Status Code: {response.status_code}")
        log.info(f"Response Body: {response.text}")

        assert response.status_code == expected_status, f"Expected {expected_status}, got {response.status_code}"

        if expected_status == 204:

            assert not response.content, "Expected no content on successful delete"
            log.info("Permission deleted successfully.")

        elif expected_status == 404:
            json_data = response.json()
            assert json_data.get("error_code") == "E404", "Expected error_code 'E404'"
            assert "not found" in json_data.get("message", "").lower()
            log.info("Error: %s", json_data.get("message"))

        else:
            pass

    except Exception as e:
        pytest.fail(f"Test failed due to exception: {str(e)}")


@pytest.mark.parametrize("test_case", get_test_cases("list_management_permissions"))
def test_list_management_permissions(test_case):
    """
    Test listing management permissions using JSON test data.
    """
    page = test_case.get("page")
    page_size = test_case.get("page_size")
    expected_status = test_case.get("expected_status")

    try:
        response = api.list_management_permissions(
            token=valid_token,
            page=page,
            page_size=page_size
        )

        log.info(f"Request URL: {response.request.url}")
        log.info(f"Status Code: {response.status_code}")
        log.info(f"Response Body: {response.text}")

        assert response.status_code == expected_status, f"Expected {expected_status}, got {response.status_code}"

        json_data = response.json()

        if expected_status == 200:
            assert json_data.get("status") == 200
            assert isinstance(json_data.get("data"), list)
            assert "page" in json_data
            assert "page_size" in json_data
            assert "total_pages" in json_data
            log.info(f"Permissions returned: {len(json_data['data'])}")

        elif expected_status == 422:
            assert "detail" in json_data or "error_code" in json_data
            log.warning(f"Validation error: {json_data}")

    except Exception as e:
        log.error(f"Exception for input page={page}, page_size={page_size}: {e}")
        pytest.fail(f"Unexpected error: {str(e)}")


@pytest.mark.parametrize("test_case", get_test_cases("create_permission_group"))
def test_create_permission_group(test_case):
    """
    Test creating permission group using JSON test data.
    """
    group_data = test_case.get("group_data")
    expected_status = test_case.get("expected_status")

    try:
        response = api.create_management_permission_group(token=valid_token, group_data=group_data)

        log.info(f"Request URL: {response.request.url}")
        log.info(f"Status Code: {response.status_code}")
        log.info(f"Response Body: {response.text}")

        assert response.status_code == expected_status, f"Expected {expected_status}, got {response.status_code}"

        json_data = response.json()

        if expected_status == 201:
            assert json_data.get("status") == 201
            assert "data" in json_data
            log.info(f"Created Permission Group: {json_data['data']}")

        elif expected_status == 422:
            assert "detail" in json_data or "error_code" in json_data
            log.warning(f"Validation error: {json_data}")

    except Exception as e:
        log.error(f"Exception while creating permission group: {e}")
        pytest.fail(f"Unexpected error occurred: {str(e)}")


@pytest.mark.parametrize("test_case", get_test_cases("get_management_permission_group"))
def test_get_management_permission_group(test_case):
    """
    Test retrieving a management permission group by group ID using JSON test data.
    """
    group_id = test_case.get("group_id")
    expected_status = test_case.get("expected_status")

    try:
        response = api.get_management_permission_group(token=valid_token, group_id=group_id)

        log.info(f"Request URL: {response.request.url}")
        log.info(f"Status Code: {response.status_code}")
        log.info(f"Response Body: {response.text}")

        assert response.status_code == expected_status, f"Expected {expected_status} but got {response.status_code}"

        json_data = response.json()

        if expected_status == 200:
            assert json_data.get("status") == 200
            assert "data" in json_data
            log.info(f"Permission Group Data: {json_data['data']}")

        elif expected_status == 404:
            assert json_data.get("error_code") == "E404"
            log.warning(f"Not Found: {json_data.get('message')}")

        elif expected_status == 422:
            assert "detail" in json_data or "error_code" in json_data
            log.warning(f"Validation Error: {json_data}")

    except Exception as e:
        log.error(f"Exception occurred: {e}")
        pytest.fail(f"Unexpected exception: {str(e)}")


@pytest.mark.parametrize("case", get_test_cases("update_permission_group_cases"))
def test_update_management_permission_group(case):
    """
        Test updating a management permission group.

        Args:
            case (dict): Contains group_id, update_data, and expected_status.
        """
    group_id = case["group_id"]
    update_data = case["update_data"]
    expected_status = case["expected_status"]

    try:
        response = api.update_management_permission_group(
            token=valid_token,
            group_id=group_id,
            update_data=update_data
        )

        assert response.status_code == expected_status, f"Expected {expected_status}, got {response.status_code}"
        json_data = response.json()

        if expected_status == 200:
            assert "status" in json_data
            assert "message" in json_data
            assert "data" in json_data
            log.info(f"Successfully updated permission group: {json_data['data']}")

        elif expected_status == 404:
            assert json_data.get("error_code") == "E404"
            log.info(f"Group not found: {json_data}")

        elif expected_status == 422:
            assert "detail" in json_data or "error_code" in json_data
            log.info(f"Validation error: {json_data}")

    except Exception as e:
        log.error(f"Test failed for group_id={group_id}, update_data={update_data}: {str(e)}")
        pytest.fail(f"Unexpected exception: {str(e)}")


@pytest.mark.parametrize("case", get_test_cases("delete_permission_group"))
def test_delete_management_permission_group(case):
    """
        Test deleting a management permission group.

        Args:
            case (dict): Contains group_id and expected_status.
        """
    group_id = case["group_id"]
    expected_status = case["expected_status"]

    try:
        response = api.delete_management_permission_group(
            token=valid_token,
            group_id=group_id
        )

        assert response.status_code == expected_status, f"Expected {expected_status}, got {response.status_code}"
        json_data = response.json()

        if expected_status == 200:
            assert "status" in json_data
            assert "message" in json_data
            log.info(f"Deleted group ID: {group_id}")

        elif expected_status == 404:
            assert json_data.get("error_code") == "E404"
            log.info(f"Not found for group ID: {group_id}")

        elif expected_status == 422:
            assert "detail" in json_data or "error_code" in json_data
            log.info(f"Validation error for group ID: {group_id}")

    except Exception as e:
        log.error(f"Exception while deleting group ID {group_id}: {str(e)}")
        pytest.fail(f"Exception occurred: {str(e)}")


@pytest.mark.parametrize("case", get_test_cases("list_permission_groups"))
def test_list_permission_groups(case):
    """
        Test listing management permission groups.

        Args:
            case (dict): Contains page, page_size, and expected_status.
        """
    page = case["page"]
    page_size = case["page_size"]
    expected_status = case["expected_status"]

    try:
        response = api.list_permission_groups(
            token=valid_token,
            page=page,
            page_size=page_size
        )

        assert response.status_code == expected_status, f"Expected {expected_status}, got {response.status_code}"
        json_data = response.json()

        if expected_status == 200:
            assert all(k in json_data for k in ("status", "message", "data", "page", "page_size"))
            assert isinstance(json_data["data"], list)
            log.info(f"Fetched {len(json_data['data'])} permission groups.")

        elif expected_status == 422:
            assert "detail" in json_data or "error_code" in json_data
            log.info(f"Validation failed for page={page}, page_size={page_size}: {json_data}")

    except Exception as e:
        log.error(f"Exception for page={page}, page_size={page_size}: {e}")
        pytest.fail(f"Unexpected exception: {e}")


@pytest.mark.parametrize("case", get_test_cases("assign_user_role"))
def test_assign_user_role(case):
    """
        Test assigning a role to a user.

        Args:
            case (dict): Contains payload and expected_status.
        """
    payload = case["payload"]
    expected_status = case["expected_status"]

    try:
        response = api.assign_user_role(token=valid_token, payload=payload)
        assert response.status_code == expected_status, f"Expected {expected_status}, got {response.status_code}"

        json_data = response.json()

        if expected_status == 201:
            assert all(k in json_data for k in ("status", "message", "data"))
            log.info(f"User role assigned successfully: {json_data['data']}")

        elif expected_status == 422:
            assert "detail" in json_data or "error_code" in json_data
            log.info(f"Validation error: {json_data}")

    except Exception as e:
        log.error(f"Exception during role assignment with payload={payload}: {e}")
        pytest.fail(f"Test failed due to unexpected exception: {e}")


@pytest.mark.parametrize("case", get_test_cases("get_user_role_assignment"))
def test_get_user_role_assignment(case):
    """
    Test fetching a user-role assignment using full test case dict with error handling.
    """
    user_id = case["user_id"]
    role_id = case["role_id"]
    expected_status = case["expected_status"]

    try:
        response = api.get_user_role_assignment(token=valid_token, user_id=user_id, role_id=role_id)
        assert response.status_code == expected_status, f"Expected {expected_status}, got {response.status_code}"

        json_data = response.json()

        if expected_status == 200:
            assert all(k in json_data for k in ("status", "message", "data"))
        elif expected_status == 404:
            assert json_data.get("error_code") == "E404"
        elif expected_status == 422:
            assert "detail" in json_data or "error_code" in json_data

    except AssertionError as ae:
        pytest.fail(f"Assertion failed for test case: {case}\nError: {ae}")
    except Exception as e:
        pytest.fail(f"Unexpected error for test case: {case}\nException: {e}")


@pytest.mark.parametrize("case", get_test_cases("update_user_role_assignment"))
def test_update_user_role_assignment(case):
    """
    Test updating user-role assignments using JSON-based test cases.
    """
    user_id = case["user_id"]
    role_id = case["role_id"]
    update_data = case["update_data"]
    expected_status = case["expected_status"]

    try:
        response = api.update_user_role_assignment(
            token=valid_token,
            user_id=user_id,
            role_id=role_id,
            update_data=update_data
        )

        assert response.status_code == expected_status, f"Expected {expected_status}, got {response.status_code}"
        json_data = response.json()

        if expected_status == 200:
            assert all(k in json_data for k in ("status", "message", "data"))
        elif expected_status == 404:
            assert json_data.get("error_code") == "E404"
        elif expected_status == 422:
            assert "detail" in json_data or "error_code" in json_data

    except AssertionError as ae:
        pytest.fail(f"Assertion failed for test case: {case}\nError: {ae}")
    except Exception as e:
        pytest.fail(f"Unexpected exception for test case: {case}\nError: {e}")


@pytest.mark.parametrize("case", get_test_cases("delete_user_role_assignment"))
def test_delete_user_role_assignment(case):
    """
    Test deleting a user-role assignment using JSON-based parameterized test cases.
    """
    user_id = case["user_id"]
    role_id = case["role_id"]
    expected_status = case["expected_status"]

    try:
        response = api.delete_user_role_assignment(
            token=valid_token,
            user_id=user_id,
            role_id=role_id
        )

        assert response.status_code == expected_status, f"Expected {expected_status}, got {response.status_code}"
        json_data = response.json()

        if expected_status == 200:
            assert "message" in json_data
            assert "status" in json_data or "success" in json_data
        elif expected_status == 404:
            assert json_data.get("error_code") == "E404"
        elif expected_status == 422:
            assert "detail" in json_data or "error_code" in json_data

    except AssertionError as ae:
        pytest.fail(f"Assertion failed for test case: {case}\nError: {ae}")
    except Exception as e:
        pytest.fail(f"Unexpected error for test case: {case}\nException: {e}")


@pytest.mark.parametrize("case", get_test_cases("list_user_roles"))
def test_list_user_roles(case):
    """
    Test listing user roles with pagination using JSON-based test cases.
    """
    page = case["page"]
    page_size = case["page_size"]
    expected_status = case["expected_status"]

    try:
        response = api.list_user_roles(
            token=valid_token,
            page=page,
            page_size=page_size
        )

        assert response.status_code == expected_status, f"Expected {expected_status}, got {response.status_code}"
        json_data = response.json()

        if expected_status == 200:

            assert "status" in json_data
            assert "message" in json_data
            assert "data" in json_data
            assert isinstance(json_data["data"], list)
            assert "total" in json_data
            assert "page" in json_data
            assert "page_size" in json_data
            assert "total_pages" in json_data
        elif expected_status == 422:
            assert "detail" in json_data or "error_code" in json_data

    except AssertionError as ae:
        pytest.fail(f"Assertion failed for test case: {case}\nError: {ae}")
    except Exception as e:
        pytest.fail(f"Unexpected error for test case: {case}\nException: {e}")


@pytest.mark.parametrize("case", get_test_cases("get_audit_log_by_id"))
def test_get_audit_log_by_id(case):
    """
    Test fetching an audit log by ID using JSON-driven test cases.
    """
    log_id = case["log_id"]
    expected_status = case["expected_status"]

    try:
        response = api.get_audit_log_by_id(token=valid_token, log_id=log_id)
        assert response.status_code == expected_status, f"Expected {expected_status}, got {response.status_code}"

        json_data = response.json()

        if expected_status == 200:
            assert "status" in json_data
            assert "message" in json_data
            assert "data" in json_data

        elif expected_status in (404, 422):
            assert "message" in json_data or "detail" in json_data or "error_code" in json_data

    except AssertionError as ae:
        pytest.fail(f"Assertion failed for case: {case}\nError: {ae}")
    except Exception as e:
        pytest.fail(f"Unexpected error for case: {case}\nException: {e}")


@pytest.mark.parametrize("case", get_test_cases("create_gym"))
def test_create_gym(auth_token_fixture, case):
    """
    Test gym creation using parameterized data from JSON.
    """
    gym_data = case["gym_data"]
    expected_status = case["expected_status"]

    try:
        response = api.create_gym(token=auth_token_fixture, gym_payload=gym_data)
        assert response.status_code == expected_status, \
            f"Expected {expected_status}, got {response.status_code}"

        json_data = response.json()

        if expected_status == 201:
            assert "status" in json_data
            assert "message" in json_data
            assert "data" in json_data
            assert json_data["data"]["name"] == gym_data.get("name")

        elif expected_status == 422:
            assert "message" in json_data
            assert "error_code" in json_data

    except AssertionError as ae:
        pytest.fail(f"Assertion failed for case: {case}\nError: {ae}")
    except Exception as e:
        pytest.fail(f"Unexpected error for case: {case}\nException: {e}")


@pytest.mark.parametrize("case", get_test_cases("get_gym_by_id"))
def test_get_gym_by_id(auth_token_fixture, case):
    """
    Test fetching a gym by ID with various inputs.
    """
    gym_id = case["gym_id"]
    expected_status = case["expected_status"]

    try:
        response = api.get_gym_by_id(token=auth_token_fixture, gym_id=gym_id)
        assert response.status_code == expected_status, (
            f"Expected {expected_status}, got {response.status_code}"
        )

        json_data = response.json()

        if expected_status == 200:
            assert all(k in json_data for k in ("status", "message", "data"))
            assert isinstance(json_data["data"], dict)
            assert "id" in json_data["data"]
            assert json_data["data"]["id"] == gym_id

        elif expected_status == 404:
            assert "message" in json_data
            assert json_data["message"] == "Gym not found"

        elif expected_status == 422:
            assert "detail" in json_data or "message" in json_data

    except AssertionError as ae:
        pytest.fail(f"Assertion failed for case: {case}\nError: {ae}")
    except Exception as e:
        pytest.fail(f"Unexpected exception for case: {case}\nError: {e}")


@pytest.mark.parametrize("case", get_test_cases("update_gym"))
def test_update_gym(case):
    """
        Test updating a gym.

        Args:
            case (dict): Contains gym_id, payload, and expected_status.
        """
    gym_id = case["gym_id"]
    payload = case["payload"]
    expected_status = case["expected_status"]

    try:
        response = api.update_gym(token=valid_token, gym_id=gym_id, payload=payload)
        assert response.status_code == expected_status, f"Expected {expected_status}, got {response.status_code}"

        json_data = response.json()

        if expected_status == 200:
            assert all(k in json_data for k in ("status", "message", "data"))
            assert json_data["data"]["id"] == gym_id

        elif expected_status == 404:
            assert "message" in json_data
            assert json_data["message"] == "Gym not found"

        elif expected_status == 422:
            assert "detail" in json_data or "message" in json_data

    except AssertionError as ae:
        pytest.fail(f"Assertion failed for case: {case}\nError: {ae}")
    except Exception as e:
        pytest.fail(f"Unexpected error for case: {case}\nError: {e}")


@pytest.mark.parametrize("case", get_test_cases("delete_gym_cases.json"))
def test_delete_gym(case):
    """
        Test deleting a gym.

        Args:
            case (dict): Contains gym_id and expected_status.
        """
    gym_id = case["gym_id"]
    expected_status = case["expected_status"]

    response = api.delete_gym(token=valid_token, gym_id=gym_id)
    assert response.status_code == expected_status, f"Expected {expected_status}, got {response.status_code}"

    if expected_status == 204:
        assert response.text.strip() == "", "Expected empty body for 204"
    else:
        json_data = response.json()
        if expected_status == 404:
            assert json_data.get("message") == "Gym not found", "Expected message: Gym not found"
        elif expected_status == 422:
            assert "detail" in json_data or "message" in json_data, "Expected 'detail' or 'message' in 422"


@pytest.mark.parametrize("params, expected_status", get_test_cases("list_gyms"))
def test_list_gyms(params, expected_status):
    """
        Test listing gyms with pagination.

        Args:
            params (dict): Query parameters for listing gyms.
            expected_status (int): Expected HTTP response status code.
        """
    try:
        response = api.list_gyms(token=valid_token, params=params)
        assert response.status_code == expected_status, f"Expected {expected_status}, got {response.status_code}"

        json_data = response.json()

        if expected_status == 200:
            required_keys = ["status", "message", "data"]
            for key in required_keys:
                assert key in json_data, f"Missing key '{key}' in response"
            assert isinstance(json_data["data"], list)

            for pagination_key in ["total", "page", "page_size", "total_pages"]:
                assert pagination_key in json_data, f"Missing pagination key: {pagination_key}"

        elif expected_status == 422:
            assert "detail" in json_data or "message" in json_data, "Expected validation error keys"

    except Exception as e:
        pytest.fail(f"Test failed with exception: {str(e)}")


@pytest.mark.parametrize("gym_id, user_id, expected_status", get_test_cases("invite_user_to_gym"))
def test_invite_user_to_gym(gym_id, user_id, expected_status):
    """
       Test inviting a user to a gym.

       Args:
           gym_id (str): The ID of the gym.
           user_id (str): The ID of the user to invite.
           expected_status (int): Expected HTTP response status code.
       """
    try:
        response = api.invite_user_to_gym(token=valid_token, gym_id=gym_id, user_id=user_id)
        assert response.status_code == expected_status, f"Expected {expected_status}, got {response.status_code}"

        json_data = response.json()

        if expected_status == 200:
            for key in ["status", "message", "data"]:
                assert key in json_data, f"Missing key '{key}' in response"
        elif expected_status in [404, 409, 422]:
            assert "message" in json_data, "Expected 'message' key in error response"

    except Exception as e:
        pytest.fail(f"Unexpected exception occurred: {str(e)}")


@pytest.mark.parametrize("gym_id, expected_status", get_test_cases("list_users_for_gym"))
def test_list_users_for_gym(auth_token_fixture, gym_id, expected_status):
    """
        Test listing users associated with a gym.

        Args:
            auth_token_fixture (str): Authentication token fixture.
            gym_id (str): The ID of the gym.
            expected_status (int): Expected HTTP response status code.
        """
    try:
        response = api.list_users_for_gym(token=auth_token_fixture, gym_id=gym_id)
        assert response.status_code == expected_status, f"Expected {expected_status}, got {response.status_code}"

        json_data = response.json()

        if expected_status == 200:
            assert "status" in json_data, "'status' not in response"
            assert "message" in json_data, "'message' not in response"
            assert isinstance(json_data.get("data"), list), "'data' should be a list"

        elif expected_status == 404:
            assert json_data.get("message") == "Gym not found", "Expected 'Gym not found' message"

        elif expected_status == 422:
            assert "detail" in json_data, "'detail' key missing in validation error response"

    except Exception as e:
        pytest.fail(f"Unexpected exception occurred: {str(e)}")


@pytest.mark.parametrize("gym_id, user_id, expected_status", get_test_cases("remove_user_from_gym"))
def test_remove_user_from_gym(auth_token_fixture, gym_id, user_id, expected_status):
    """
        Test removing a user from a gym.

        Args:
            auth_token_fixture (str): Authentication token fixture.
            gym_id (str): The ID of the gym.
            user_id (str): The ID of the user to remove.
            expected_status (int): Expected HTTP response status code.
        """
    try:
        response = api.remove_user_from_gym(token=auth_token_fixture, gym_id=gym_id, user_id=user_id)
        assert response.status_code == expected_status, f"Expected {expected_status}, got {response.status_code}"

        json_data = response.json()

        if expected_status == 200:
            assert "status" in json_data, "'status' key missing in response"
            assert "message" in json_data, "'message' key missing in response"

        elif expected_status == 404:
            assert json_data.get("message") == "User not found or not associated with gym", \
                "Expected message for user not found or not associated"

        elif expected_status == 422:
            assert "detail" in json_data, "'detail' key missing in validation error response"

    except Exception as e:
        pytest.fail(f"Test failed due to unexpected exception: {str(e)}")
