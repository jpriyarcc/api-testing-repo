"""
Management GYM User API
"""
import json

import os

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


global_access_token = ""
global_refresh_token = ""


@pytest.mark.sanity
@pytest.mark.parametrize("user_data, expected_status", get_test_cases("create_gym_user"))
def test_create_gym_user(user_data, expected_status):
    try:
        response = api.create_gym_user(user_data=user_data)
        assert response.status_code == expected_status, f"Expected {expected_status}, got {response.status_code}"

        json_resp = response.json()

        if expected_status == 201:
            assert json_resp.get("status") == 201, "Expected status 201 in response body"
            assert "message" in json_resp, "'message' key missing"
            assert "data" in json_resp, "'data' key missing"
            assert "email" in json_resp["data"], "'email' missing in user data"

        elif expected_status == 409:
            assert json_resp.get("message") == "Email is already registered", "Incorrect conflict message"

        elif expected_status == 422:
            assert "detail" in json_resp, "'detail' missing in validation error response"

    except Exception as e:
        pytest.fail(f"Test failed with unexpected exception: {str(e)}")


@pytest.mark.sanity
@pytest.mark.parametrize(
    "token, expected_status, expected_message",
    get_test_cases("verify_gym_email")
)
def test_verify_gym_email(token, expected_status, expected_message):
    try:
        response = api.verify_gym_email(token=token)
        assert response.status_code == expected_status, f"Expected status {expected_status}, got {response.status_code}"

        json_resp = response.json()

        if expected_status == 200:
            assert json_resp.get("status") == 200, "'status' should be 200 in response body"
            assert "message" in json_resp, "'message' key missing in 200 response"

        elif expected_status in (400, 404):
            assert json_resp.get(
                "message") == expected_message, f"Expected message '{expected_message}', got '{json_resp.get('message')}'"
            assert "error_code" in json_resp, "'error_code' missing"
            assert "correlation_id" in json_resp, "'correlation_id' missing"

        elif expected_status == 422:
            assert "detail" in json_resp, "'detail' key missing in validation error"

    except Exception as e:
        pytest.fail(f"Unexpected exception occurred: {e}")


@pytest.mark.regression
@pytest.mark.parametrize(
    "email, expected_status, expected_message",
    get_test_cases("resend_verification_email")

)
def test_resend_verification_email(email, expected_status, expected_message):
    try:
        response = api.resend_verification_email(email=email)
        assert response.status_code == expected_status

        json_resp = response.json()

        if expected_status == 200:
            assert json_resp.get("status") == 200
            assert "message" in json_resp
        elif expected_status in (404, 422):
            assert json_resp.get("message") == expected_message
            assert "error_code" in json_resp
            assert "correlation_id" in json_resp

    except AssertionError as ae:
        pytest.fail(f"Assertion failed for email: {email}, error: {ae}")
    except Exception as e:
        pytest.fail(f"Unexpected error for email: {email}, error: {e}")


@pytest.mark.regression
@pytest.mark.parametrize(
    "email, expected_status, expected_message",
    get_test_cases("request_password_reset")
)
def test_request_password_reset(email, expected_status, expected_message):
    try:
        response = api.request_password_reset(email=email)
        assert response.status_code == expected_status

        json_resp = response.json()

        if expected_status == 200:
            assert json_resp.get("status") == 200
            assert "message" in json_resp

        elif expected_status == 404:
            assert json_resp.get("message") == expected_message
            assert json_resp.get("error_code") == "E404"
            assert "correlation_id" in json_resp

        elif expected_status == 422:
            assert "detail" in json_resp

    except AssertionError as ae:
        pytest.fail(f"Assertion failed for email: {email}, error: {ae}")
    except Exception as e:
        pytest.fail(f"Unexpected error for email: {email}, error: {e}")


@pytest.mark.negative
@pytest.mark.parametrize(
    "token, password, cpassword, expected_status, expected_message",
    get_test_cases("reset_gym_password")
)
def test_reset_gym_password(token, password, cpassword, expected_status, expected_message):
    try:
        response = api.reset_gym_password(token=token, password=password, cpassword=cpassword)
        assert response.status_code == expected_status, f"Expected {expected_status}, got {response.status_code}"

        json_resp = response.json()

        if expected_status == 200:
            assert json_resp.get("status") == 200, "'status' missing or incorrect"
            assert "message" in json_resp, "'message' not found"

        elif expected_status in [400, 404, 500]:
            assert json_resp.get(
                "message") == expected_message, f"Expected '{expected_message}', got '{json_resp.get('message')}'"
            assert "error_code" in json_resp
            assert "correlation_id" in json_resp

        elif expected_status == 422:
            assert "detail" in json_resp

    except AssertionError as ae:
        pytest.fail(f"Assertion failed for token={token}: {ae}")
    except Exception as e:
        pytest.fail(f"Unexpected error for token={token}: {e}")


@pytest.mark.sanity
@pytest.mark.dependency(name="login")
@pytest.mark.parametrize("email, password",
                         get_test_cases("gym_login_credentials")
                         )
def test_gym_login_dynamic(email, password):
    """
    Logs in a gym user and stores the access/refresh tokens globally.
    """
    global global_access_token, global_refresh_token

    try:
        login_response = api.login_gym_user(email=email, password=password)
        assert login_response.status_code == 200, f"Login failed: {login_response.text}"

        json_data = login_response.json()
        log.info(f"Login Response:\n{json.dumps(json_data, indent=2)}")

        access_token = json_data.get("data", {}).get("access_token")
        refresh_token = json_data.get("data", {}).get("refresh_token")

        assert access_token, "Access token not found"
        assert refresh_token, "Refresh token not found"

        global_access_token = access_token
        global_refresh_token = refresh_token

    except AssertionError as ae:
        log.error(f"Assertion failed: {ae}")
        raise
    except Exception as e:
        log.exception("Unexpected error occurred:")
        raise


@pytest.mark.regression
@pytest.mark.dependency(depends=["login"])
def test_gym_refresh_token():
    """
    Uses the global refresh token to obtain a new access token.
    """
    global global_refresh_token

    try:
        # Validate if refresh token is available
        assert global_refresh_token, "Global refresh token not set. Run login test first."

        # Call API to refresh token
        response = api.refresh_gym_token(refresh_token=global_refresh_token)
        assert response.status_code == 200, f"Token refresh failed: {response.text}"

        response_data = response.json()
        log.info(f"Refresh Token Response:{json.dumps(response_data, indent=2)}")

        access_token = response_data.get("access_token") or response_data.get("data", {}).get("access_token")
        assert access_token, "Access token not found in refresh response."

        log.info(f"New Access Token: {access_token}")

    except (AssertionError, json.JSONDecodeError) as e:
        log.error(f"Validation failed: {e}")
        raise
    except Exception as e:
        log.exception("Unexpected error during token refresh:")
        raise


@pytest.mark.regression
@pytest.mark.dependency(depends=["login"])
def test_gym_logout():
    """
    Validates gym user logout using the global access token.
    """
    global global_access_token

    try:
        assert global_access_token, "Access token not set. Run login test first."

        response = api.gym_logout(global_access_token)
        assert response.status_code == 200, f"Logout failed: {response.status_code} - {response.text}"

        json_data = response.json()
        log.info(f"Logout Response: {json.dumps(json_data, indent=2)}")

        assert "status" in json_data, "'status' field missing in response"
        assert "message" in json_data, "'message' field missing in response"

    except Exception as e:
        log.exception(f"Gym logout test failed: {e}")
        raise


global_gym_user_id = ""


@pytest.mark.sanity
@pytest.mark.dependency(depends=["login"])
@pytest.mark.dependency(name="loginuser")
def test_get_current_gym_user():
    """
    Test to retrieve details of the currently logged-in gym user.
    """
    global global_access_token, global_gym_user_id

    try:
        assert global_access_token, "Access token not set. Run login test first."

        response = api.get_gym_user_profile(global_access_token)
        assert response.status_code == 200, f"Failed to fetch profile: {response.status_code} - {response.text}"

        json_data = response.json()
        log.info(f"Gym User Profile Response: {json.dumps(json_data, indent=2)}")

        assert all(key in json_data for key in ("status", "message", "data")), "Missing keys in response"

        user_data = json_data["data"]
        assert "email" in user_data, "'email' missing in user data"
        assert "id" in user_data, "'id' missing in user data"

        global_gym_user_id = user_data["id"]
        log.info(f"Gym User ID stored: {global_gym_user_id}")

    except Exception as e:
        log.exception(f"Failed to get current gym user: {e}")
        raise


@pytest.mark.regression
@pytest.mark.dependency(depends=["login"])
@pytest.mark.dependency(depends=["loginuser"])
def test_get_gym_user_by_id():
    """
    Test to verify retrieving gym user details using the user ID.
    """
    global global_access_token, global_gym_user_id

    try:
        assert global_access_token, "Access token is missing. Run login test first."
        assert global_gym_user_id, "User ID is missing. Ensure it is set before running this test."

        response = api.get_gym_user_by_id(global_access_token, global_gym_user_id)
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}: {response.text}"

        res_json = response.json()
        log.info(f"Response JSON:{json.dumps(res_json, indent=2)}")

        assert res_json.get("status") == 200, "Unexpected status field in response"
        assert "data" in res_json, "'data' missing in response"

        user_data = res_json["data"]
        assert user_data.get("id") == global_gym_user_id, "Returned user ID does not match expected"
        assert "email" in user_data, "'email' missing in user data"

        log.info(f"Gym User fetched by ID: {user_data}")

    except Exception as e:
        log.exception(f"Failed to get user by ID: {e}")
        raise


@pytest.mark.regression
@pytest.mark.dependency(depends=["login"])
@pytest.mark.dependency(depends=["loginuser"])
@pytest.mark.parametrize("payload, expected_status", get_test_cases("update_gym_user_tests"))
def test_update_gym_user_by_id(payload, expected_status):
    """
    Test updating a gym user with various payloads using global token & user_id.
    """
    try:
        assert global_gym_user_id, "global_gym_user_id not set. Run user creation or fetch script."
        assert global_access_token, "global_access_token not set. Run login test first."

        # Handle placeholders like "A*500"
        final_payload = {
            k: ("A" * 500 if isinstance(v, str) and v == "A*500" else v)
            for k, v in payload.items()
        }

        response = api.update_gym_user_by_id(global_access_token, global_gym_user_id, final_payload)
        assert response.status_code == expected_status, f"Expected {expected_status}, got {response.status_code}"

        json_data = response.json()

        if expected_status == 200:
            assert "status" in json_data, "'status' missing in response"
            assert "message" in json_data, "'message' missing in response"
            assert isinstance(json_data.get("data"), dict), "'data' should be a dictionary"

        elif expected_status == 422:
            assert "detail" in json_data, "'detail' missing in response"
            assert isinstance(json_data["detail"], list), "'detail' should be a list"
            assert any(
                err.get("type") == "string_too_long" and "first_name" in err.get("loc", [])
                for err in json_data["detail"]
            ), "Expected validation error for 'first_name'"

    except AssertionError as ae:
        pytest.fail(f"Assertion failed: {ae}")

    except Exception as e:
        pytest.fail(f"Unexpected error occurred: {e}")


@pytest.mark.regression
@pytest.mark.dependency(depends=["login"])
@pytest.mark.dependency(depends=["loginuser"])
def test_delete_gym_user_by_id():
    """
    Test to delete a gym user by ID.
    """
    try:
        assert global_gym_user_id, "User ID not set. Please create a user first."
        assert global_access_token, "Token not set. Please login first."

        response = api.delete_gym_user(global_gym_user_id, global_access_token)
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"

        json_data = response.json()
        assert json_data.get("success") is True, "Expected 'success' to be True"
        assert "message" in json_data, "'message' key missing in response"

    except Exception as e:
        pytest.fail(f"Test failed: {e}")


@pytest.mark.sanity
@pytest.mark.dependency(depends=["login"])
def test_list_gym_users_basic():
    """
    Test the basic listing of gym users, verifying
    pagination and response structure for a successful list endpoint.
    """
    global global_access_token
    assert global_access_token, "Access token is not set. Please run login test first."

    try:
        response = api.list_gym_users(global_access_token)
        assert response.status_code == 200, f"Expected HTTP 200, got {response.status_code}"
        json_data = response.json()

        for key in ("status", "message", "data", "total", "page", "page_size", "total_pages"):
            assert key in json_data, f"Response missing '{key}'"

        assert isinstance(json_data["data"], list), f"'data' expected list, got {type(json_data['data'])}"

        log.info("Gym users listed successfully with correct response structure.")

    except AssertionError:

        log.error("Assertion failed in test_list_gym_users_basic", exc_info=True)
        raise
    except Exception as e:
        log.error("Unexpected exception in test_list_gym_users_basic", exc_info=True)
        pytest.fail(f"Unexpected exception occurred: {e}")


@pytest.mark.regression
@pytest.mark.dependency(depends=["login"])
@pytest.mark.dependency(depends=["loginuser"])
@pytest.mark.parametrize("case", get_test_cases("assign_gym_user_role"))
def test_assign_gym_user_role(case):
    """
    Validate assigning a role to a gym user using JSON-driven test cases.
    """
    global global_access_token
    assert global_access_token, "Token not set. Run login test first."

    try:
        user_id = case["user_id"]
        role_id = case["role_id"]
        expected_status = case["expected_status"]

        response = api.assign_gym_user_role(
            token=global_access_token,
            user_id=user_id,
            role_id=role_id
        )

        status = response.status_code
        json_data = response.json()

        assert status == expected_status, f"Expected {expected_status}, got {status}"

        if status == 201:
            assert "status" in json_data
            assert "message" in json_data
            assert "data" in json_data and isinstance(json_data["data"], dict)
            log.info("Successfully assigned role to user_id=%s: %s", user_id, json_data["data"])

        elif status == 422:
            assert "detail" in json_data or "error_code" in json_data
            log.info("Validation error as expected: %s", json_data)

        elif status == 500:
            assert json_data.get("error_code") == "E500"
            assert "Unexpected server error" in json_data.get("message", "")
            log.warning("Server error occurred for input user_id=%s, role_id=%s", user_id, role_id)

        else:
            pytest.fail(f"Unhandled status {status} for case: {case}")

    except Exception as e:
        log.error("Test failed for case: %s\nError: %s", case, e, exc_info=True)
        pytest.fail(f"Unexpected error occurred: {e}")


@pytest.mark.regression
@pytest.mark.dependency(depends=["login"])
@pytest.mark.dependency(depends=["loginuser"])
@pytest.mark.parametrize("case", get_test_cases("get_gym_user_role"))
def test_get_gym_user_role(case):
    """
    Validate retrieval of a gym user-role assignment using JSON-driven test cases.
    """
    global global_access_token
    assert global_access_token, "Access token not set. Run login test first."

    try:
        # Make the API call
        response = api.get_gym_user_role(
            token=global_access_token,
            user_id=case["user_id"],
            role_id=case["role_id"]
        )

        # Validate the response status code
        status = response.status_code
        assert status == case["expected_status"], f"Expected HTTP {case['expected_status']}, got {status}"

        json_data = response.json()

        if status == 200:
            assert "status" in json_data and "message" in json_data and "data" in json_data
            assert isinstance(json_data["data"], dict)
            log.info("User-role retrieved successfully: %s", json_data["data"])

        elif status == 404:
            assert json_data.get("error_code") == "E404"
            assert "not found" in json_data.get("message", "").lower()
            log.info("Resource not found as expected for case: %s", case)

        elif status == 422:
            assert "detail" in json_data or "error_code" in json_data
            log.info("Validation error as expected for case: %s", case)

        else:
            pytest.fail(f"Unhandled status {status} for case: {case}")

    except Exception as e:
        # Log the exception and fail the test
        log.error("Test failed for case %s: %s", case, e, exc_info=True)
        pytest.fail(f"Test failed due to exception: {e}")


@pytest.mark.regression
@pytest.mark.dependency(depends=["login"])
@pytest.mark.dependency(depends=["loginuser"])
@pytest.mark.parametrize("case", get_test_cases("update_gym_user_role"))
def test_update_gym_user_role(case):
    """
    Test the .
    """
    global global_access_token
    assert global_access_token, "Access token not set. Please run login test first."

    try:
        response = api.update_gym_user_role(
            token=global_access_token,
            user_id=case["user_id"],
            role_id=case["role_id"],
            update_data=case["update_data"]
        )

        status = response.status_code
        assert status == case["expected_status"], \
            f"Expected {case['expected_status']}, got {status}"

        json_data = response.json()

        if status == 200:
            assert "status" in json_data and "message" in json_data and "data" in json_data
            assert isinstance(json_data["data"], dict)
            log.info("Update succeeded: %s", json_data["data"])

        elif status == 404:
            assert json_data.get("error_code") == "E404"
            assert "not found" in json_data.get("message", "").lower()
            log.info("404 Not Found as expected for case: %s", case)

        elif status == 422:
            assert "detail" in json_data or "error_code" in json_data
            log.info("Validation error as expected for case: %s", case)

        else:
            pytest.fail(f"Unhandled status code {status} for case: {case}")

    except Exception as e:
        log.error("Test failed for case %s: %s", case, e, exc_info=True)
        pytest.fail(f"Test failed due to exception: {e}")


@pytest.mark.sanity
@pytest.mark.dependency(depends=["login"])
@pytest.mark.dependency(depends=["loginuser"])
@pytest.mark.parametrize("case", get_test_cases("delete_gym_user_role"))
def test_delete_gym_user_role(case):
    """
    Simple and robust test for DELETE user-role assignment endpoint.
    Entire logic is inside a single try-except block.
    """
    global global_access_token
    assert global_access_token, "Access token not set. Please run login test first."

    try:
        response = api.delete_gym_user_role(
            token=global_access_token,
            user_id=case["user_id"],
            role_id=case["role_id"]
        )

        status = response.status_code
        assert status == case["expected_status"], \
            f"Expected HTTP {case['expected_status']}, got {status}"

        json_data = response.json()

        if status == 200:

            assert "status" in json_data and "message" in json_data
            log.info("Delete succeeded: %s", json_data.get("message"))

        elif status == 404:
            assert json_data.get("error_code") == "E404"
            assert "not found" in json_data.get("message", "").lower()
            log.info("404 Not Found as expected for case: %s", case)

        elif status == 422:
            assert "detail" in json_data or "error_code" in json_data
            log.info("Validation error as expected for case: %s", case)

        else:
            pytest.fail(f"Unhandled HTTP status {status} for case: {case}")

    except Exception as e:
        log.error("Test failure for case %s: %s", case, e, exc_info=True)
        pytest.fail(f"Test aborted due to exception: {e}")


@pytest.mark.regression
@pytest.mark.dependency(depends=["login"])
@pytest.mark.dependency(depends=["loginuser"])
@pytest.mark.parametrize("case", get_test_cases("list_gym_user_roles"))
def test_list_gym_user_roles(case):
    """
    Test list user-role assignments endpoint with pagination parameters.
    Entire test logic inside a single try-except block.
    """
    global global_access_token
    assert global_access_token, "Access token not set. Please run login test first."

    try:
        response = api.list_gym_user_roles(token=global_access_token, params=case["params"])

        status = response.status_code
        assert status == case["expected_status"], f"Expected {case['expected_status']}, got {status}"

        json_data = response.json()

        if status == 200:

            for key in ("status", "message", "data", "total", "page", "page_size", "total_pages"):
                assert key in json_data, f"Missing '{key}' in response"

            assert isinstance(json_data["data"], list)
            log.info("List retrieved successfully: total=%s, page=%s", json_data["total"], json_data["page"])

        elif status == 422:

            assert "detail" in json_data or "error_code" in json_data
            log.info("Validation error as expected for params: %s", case["params"])

        else:
            pytest.fail(f"Unhandled HTTP status {status} for case: {case}")

    except Exception as e:
        log.error("Test failed for case %s: %s", case, e, exc_info=True)
        pytest.fail(f"Test aborted due to exception: {e}")
