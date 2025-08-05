import logging
from tests.utils.api_client import APIClient
from tests.utils.api_data import ManagementUserCreate

log = logging.getLogger(__name__)


class ManagementUserAPIHandler(APIClient):
    def __init__(self, base_url: str, api_version: str = "v1"):
        """
        Management User API Handler.

        Args:
            base_url (str): Base URL of the API.
            api_version (str): API version (default: "v1").
        """
        super().__init__(base_url)
        self.api_version = api_version

    # ----------------- USER AUTH -----------------
    def register_user(self, user: ManagementUserCreate, timeout: int = 10):
        """
        Register a new management user.

        Args:
            user (ManagementUserCreate): User object with registration details.
            timeout (int): Request timeout in seconds (default 10).

        Returns:
            dict: Parsed JSON response from the API.
        """
        endpoint = f"/api/{self.api_version}/management/auth/register"
        payload = user.to_dict()
        try:
            return self.post(endpoint, json=payload)

        except Exception as e:
            log.error(f"User registration failed: {e}")
            raise

    def verify_email(self, token: str):
        """
        Verify user email using the provided token.

        Args:
            token (str): Email verification token.

        Returns:
            dict: API response as JSON.
        """
        endpoint = f"/api/{self.api_version}/management/auth/verify-email"
        log.info(f"Verifying email using token at endpoint: {endpoint}")
        try:
            return self.get(endpoint, params={"token": token})

        except Exception as e:
            log.error(f"Email verification failed: {e}")
            raise

    def resend_verification(self, email: str):
        """
        Resend email verification link to the user.

        Args:
            email (str): User email address.

        Returns:
            dict: API response as JSON.
        """
        endpoint = f"/api/{self.api_version}/management/auth/resend-verification"
        log.info(f"Resending email verification link for: {email}")
        try:
            resp = self.post(endpoint, json={"email": email})
            return resp
        except Exception as e:
            log.error(f"Resend verification failed: {e}")
            raise

    def forgot_password(self, email: str):
        """
        Request a password reset link.

        Args:
            email (str): User email address.

        Returns:
            dict: API response as JSON.
        """
        endpoint = f"/api/{self.api_version}/management/auth/forgot-password"
        log.info(f"Requesting password reset for email: {email}")
        try:
            resp = self.post(endpoint, json={"email": email})
            return resp
        except Exception as e:
            log.error(f"Forgot password request failed: {e}")
            raise

    def reset_password(self, token: str, password: str, cpassword: str):
        """
        Reset user password using a token.

        Args:
            token (str): Password reset token.
            password (str): New password.
            cpassword (str): Confirm password.

        Returns:
            dict: API response as JSON.
        """
        endpoint = f"/api/{self.api_version}/management/auth/password-reset"
        log.info(f"Resetting password using token at endpoint: {endpoint}")
        try:
            resp = self.post(endpoint, json={"password": password, "cpassword": cpassword})
            return resp.json()
        except Exception as e:
            log.error(f"Reset password failed: {e}")
            raise

    def login(self, email: str, password: str):
        """
        Login and retrieve an authentication token.

        Args:
            email (str): User email.
            password (str): User password.

        Returns:
            dict: API response with token.
        """
        endpoint = f"/api/{self.api_version}/management/auth/login"
        log.info(f"Logging in user: {email}")
        try:
            resp = self.post(endpoint, json={"email": email, "password": password})
            return resp
        except Exception as e:
            log.error(f"Login failed: {e}")
            raise

    def refresh_token(self, refresh_token: str):
        """
        Refresh the access token using a refresh token.

        Args:
            refresh_token (str): Refresh token.

        Returns:
            dict: API response as JSON.
        """
        endpoint = "/refresh"
        log.info(f"Initiating token refresh via endpoint: {endpoint}")

        try:
            resp = self.post(endpoint, token=refresh_token)
            log.info(f"Token refresh successful. Status Code: {resp.status_code}")
            return resp
        except Exception as e:
            log.error(f"Token refresh failed with error: {e}")
            raise

    def logout_user(self, token: str):
        """
        Logout the current authenticated user.

        Args:
            token (str): Bearer token.

        Returns:
            dict: API response as JSON.
        """
        endpoint = f"/api/{self.api_version}/management/auth/logout"
        log.info(f"Logging out user at endpoint: {endpoint}")
        try:
            resp = self.get(endpoint, token=token)
            return resp
        except Exception as e:
            log.error(f"Logout failed: {e}")
            raise

    def get_current_user(self, token: str):
        """
        Fetch details of the currently logged-in user.

        Args:
            token (str): Bearer token.

        Returns:
            dict: API response as JSON.
        """
        endpoint = f"/api/{self.api_version}/management/user/me"
        log.info(f"Fetching current user details at endpoint: {endpoint}")
        try:
            resp = self.get(endpoint, token=token)
            return resp
        except Exception as e:
            log.error(f"Fetch current user failed: {e}")
            raise

    def get_user_by_id(self, user_id: str, token: str):
        """
        Retrieve user details by user ID.

        Args:
            user_id (str): User UUID.
            token (str): Bearer token.

        Returns:
            dict: API response as JSON.
        """
        endpoint = f"/api/{self.api_version}/management/user/{user_id}"
        log.info(f"Fetching user by ID: {user_id}")
        try:
            resp = self.get(endpoint, token=token)
            return resp
        except Exception as e:
            log.error(f"Fetch user by ID failed: {e}")
            raise

    def update_user_by_id(self, user_id: str, token: str, update_payload: dict):
        """
        Update user details by ID.

        Args:
            user_id (str): User UUID.
            token (str): Bearer token.
            update_payload (dict): Fields to update.

        Returns:
            dict: API response as JSON.
        """
        endpoint = f"/api/{self.api_version}/management/user/{user_id}"
        log.info(f"Updating user ID: {user_id} with data: {update_payload}")
        try:
            resp = self.put(endpoint, json=update_payload, token=token)
            return resp
        except Exception as e:
            log.error(f"Update user failed: {e}")
            raise

    def delete_user_by_id(self, user_id: str, token: str):
        """
        Delete a user by ID.

        Args:
            user_id (str): User UUID.
            token (str): Bearer token.

        Returns:
            int: HTTP status code.
        """
        endpoint = f"/api/{self.api_version}/management/user/{user_id}"
        log.info(f"Deleting user ID: {user_id}")
        try:
            resp = self.delete(endpoint, token=token)
            return resp
        except Exception as e:
            log.error(f"Delete user failed: {e}")
            raise

    def list_management_users(self, token: str, params: dict = None):
        """
        List all management users.

        Args:
            token (str): Bearer token.
            params (dict): Optional query parameters.

        Returns:
            dict: API response as JSON.
        """
        endpoint = f"/api/{self.api_version}/management/users"
        log.info(f"Listing management users with params: {params}")
        try:
            resp = self.get(endpoint, token=token, params=params)
            return resp.json()
        except Exception as e:
            log.error(f"List management users failed: {e}")
            raise

        # ----------------- ROLE MANAGEMENT -----------------

    def list_roles(self, token: str, page: int = 1, page_size: int = 20):
        """
        List all management roles.

        Args:
            token (str): Bearer token.
            page (int): Page number (default: 1).
            page_size (int): Number of items per page (default: 20).

        Returns:
            dict: API response as JSON.
        """
        endpoint = f"/api/{self.api_version}/management/roles"
        params = {"page": page, "page_size": page_size}
        log.info(f"Listing roles: Page={page}, PageSize={page_size}")
        try:
            resp = self.get(endpoint, token=token, params=params)
            return resp.json()
        except Exception as e:
            log.error(f"List roles failed: {e}")
            raise

    def create_role(self, token: str, role_data: dict):
        """
        Create a new role.

        Args:
            token (str): Bearer token.
            role_data (dict): Role creation payload.

        Returns:
            dict: API response as JSON.
        """
        endpoint = f"/api/{self.api_version}/management/role"
        log.info(f"Creating role with data: {role_data}")
        try:
            resp = self.post(endpoint, json=role_data, token=token)
            return resp.json()
        except Exception as e:
            log.error(f"Create role failed: {e}")
            raise

    def update_role_by_id(self, token: str, role_id: str, update_data: dict):
        """
        Update an existing role by ID.

        Args:
            token (str): Bearer token.
            role_id (str): UUID of the role.
            update_data (dict): Role update payload.

        Returns:
            dict: API response as JSON.
        """
        endpoint = f"/api/{self.api_version}/management/role/{role_id}"
        log.info(f"Updating role ID: {role_id} with data: {update_data}")
        try:
            resp = self.put(endpoint, json=update_data, token=token)
            return resp.json()
        except Exception as e:
            log.error(f"Update role failed: {e}")
            raise

    def delete_role_by_id(self, token: str, role_id: str):
        """
        Delete a role by ID.

        Args:
            token (str): Bearer token.
            role_id (str): UUID of the role.

        Returns:
            int: HTTP status code.
        """
        endpoint = f"/api/{self.api_version}/management/role/{role_id}"
        log.info(f"Deleting role ID: {role_id}")
        try:
            resp = self.delete(endpoint, token=token)
            return resp.status_code
        except Exception as e:
            log.error(f"Delete role failed: {e}")
            raise

        # ----------------- PERMISSIONS -----------------

    def list_permissions(self, token: str, page: int = 1, page_size: int = 20):
        """
        List all permissions.

        Args:
            token (str): Bearer token.
            page (int): Page number (default: 1).
            page_size (int): Number of items per page (default: 20).

        Returns:
            dict: API response as JSON.
        """
        endpoint = f"/api/{self.api_version}/management/permissions"
        params = {"page": page, "page_size": page_size}
        log.info(f"Listing permissions: Page={page}, PageSize={page_size}")
        try:
            resp = self.get(endpoint, token=token, params=params)
            return resp.json()
        except Exception as e:
            log.error(f"List permissions failed: {e}")
            raise

    def create_permission(self, token: str, payload: dict):
        """
        Create a new permission.

        Args:
            token (str): Bearer token.
            payload (dict): Permission creation payload.

        Returns:
            dict: API response as JSON.
        """
        endpoint = f"/api/{self.api_version}/management/permission"
        log.info(f"Creating permission with data: {payload}")
        try:
            resp = self.post(endpoint, json=payload, token=token)
            return resp.json()
        except Exception as e:
            log.error(f"Create permission failed: {e}")
            raise

    def update_permission_by_id(self, token: str, permission_id: str, update_data: dict):
        """
        Update a permission by ID.

        Args:
            token (str): Bearer token.
            permission_id (str): UUID of the permission.
            update_data (dict): Permission update payload.

        Returns:
            dict: API response as JSON.
        """
        endpoint = f"/api/{self.api_version}/management/permission/{permission_id}"
        log.info(f"Updating permission ID: {permission_id} with data: {update_data}")
        try:
            resp = self.put(endpoint, json=update_data, token=token)
            return resp.json()
        except Exception as e:
            log.error(f"Update permission failed: {e}")
            raise

    def delete_permission_by_id(self, token: str, permission_id: str):
        """
        Delete a permission by ID.

        Args:
            token (str): Bearer token.
            permission_id (str): UUID of the permission.

        Returns:
            int: HTTP status code.
        """
        endpoint = f"/api/{self.api_version}/management/permission/{permission_id}"
        log.info(f"Deleting permission ID: {permission_id}")
        try:
            resp = self.delete(endpoint, token=token)
            return resp.status_code
        except Exception as e:
            log.error(f"Delete permission failed: {e}")
            raise

        # ----------------- PERMISSION GROUP -----------------

    def create_permission_group(self, token: str, payload: dict):
        """
        Create a new permission group.

        Args:
            token (str): Bearer token.
            payload (dict): Permission group creation payload.

        Returns:
            dict: API response as JSON.
        """
        endpoint = f"/api/{self.api_version}/management/permission-group"
        log.info(f"Creating permission group with data: {payload}")
        try:
            resp = self.post(endpoint, json=payload, token=token)
            return resp.json()
        except Exception as e:
            log.error(f"Create permission group failed: {e}")
            raise

    def update_permission_group(self, token: str, group_id: str, payload: dict):
        """
        Update a permission group by ID.

        Args:
            token (str): Bearer token.
            group_id (str): UUID of the permission group.
            payload (dict): Permission group update payload.

        Returns:
            dict: API response as JSON.
        """
        endpoint = f"/api/{self.api_version}/management/permission-group/{group_id}"
        log.info(f"Updating permission group ID: {group_id} with data: {payload}")
        try:
            resp = self.put(endpoint, json=payload, token=token)
            return resp.json()
        except Exception as e:
            log.error(f"Update permission group failed: {e}")
            raise

    def delete_permission_group(self, token: str, group_id: str):
        """
        Delete a permission group by ID.

        Args:
            token (str): Bearer token.
            group_id (str): UUID of the permission group.

        Returns:
            int: HTTP status code.
        """
        endpoint = f"/api/{self.api_version}/management/permission-group/{group_id}"
        log.info(f"Deleting permission group ID: {group_id}")
        try:
            resp = self.delete(endpoint, token=token)
            return resp.status_code
        except Exception as e:
            log.error(f"Delete permission group failed: {e}")
            raise

    def update_management_permission_group(self, token: str, group_id: str, update_data: dict):
        """
        Update an existing permission group by its UUID.
        """
        endpoint = f"/api/{self.api_version}/management/permission-group/{group_id}"
        log.info(f"Updating permission group | Endpoint: {endpoint} | Payload: {update_data}")
        try:
            resp = self.put(endpoint, token=token, json=update_data)
            log.info(
                f"Update permission group response | Status: {resp.status_code} | Body: {resp.text if resp.content else 'No content'}")
            return resp.json()
        except Exception as e:
            log.error(f"Failed to update permission group: {e}")
            raise

    def delete_management_permission_group(self, token: str, group_id: str):
        """
        Delete a permission group by its UUID.
        """
        endpoint = f"/api/{self.api_version}/management/permission-group/{group_id}"
        log.info(f"Deleting permission group | Endpoint: {endpoint}")
        try:
            resp = self.delete(endpoint, token=token)
            log.info(f"Delete permission group response | Status: {resp.status_code}")
            return resp.status_code
        except Exception as e:
            log.error(f"Failed to delete permission group: {e}")
            raise

    def list_permission_groups(self, token: str, page: int = 1, page_size: int = 20):
        """
        Retrieve a paginated list of all permission groups.
        """
        endpoint = f"/api/{self.api_version}/management/permission-groups"
        params = {"page": page, "page_size": page_size}
        log.info(f"Fetching permission groups list | Endpoint: {endpoint} | Params: {params}")
        try:
            resp = self.get(endpoint, token=token, params=params)
            log.info(f"List permission groups response | Status: {resp.status_code}")
            return resp.json()
        except Exception as e:
            log.error(f"Failed to list permission groups: {e}")
            raise

    def assign_user_role(self, token: str, payload: dict):
        """
        Assign a role to a user.
        """
        endpoint = f"/api/{self.api_version}/management/user-role"
        log.info(f"Assigning role to user | Endpoint: {endpoint} | Payload: {payload}")
        try:
            resp = self.post(endpoint, token=token, json=payload)
            log.info(f"Assign user role response | Status: {resp.status_code}")
            return resp.json()
        except Exception as e:
            log.error(f"Failed to assign user role: {e}")
            raise

    def get_user_role_assignment(self, token: str, user_id: str, role_id: str):
        """
        Retrieve a specific user-role assignment by user ID and role ID.
        """
        endpoint = f"/api/{self.api_version}/management/user-role/{user_id}/{role_id}"
        log.info(f"Fetching user-role assignment | Endpoint: {endpoint}")
        try:
            resp = self.get(endpoint, token=token)
            log.info(f"Get user-role assignment response | Status: {resp.status_code}")
            return resp.json()
        except Exception as e:
            log.error(f"Failed to fetch user-role assignment: {e}")
            raise

    def update_user_role_assignment(self, token: str, user_id: str, role_id: str, update_data: dict):
        """
        Update an existing user-role assignment.
        """
        endpoint = f"/api/{self.api_version}/management/user-role/{user_id}/{role_id}"
        log.info(f"Updating user-role assignment | Endpoint: {endpoint} | Payload: {update_data}")
        try:
            resp = self.put(endpoint, token=token, json=update_data)
            log.info(f"Update user-role assignment response | Status: {resp.status_code}")
            return resp.json()
        except Exception as e:
            log.error(f"Failed to update user-role assignment: {e}")
            raise

    def delete_user_role_assignment(self, token: str, user_id: str, role_id: str):
        """
        Delete a user-role assignment by user ID and role ID.
        """
        endpoint = f"/api/{self.api_version}/management/user-role/{user_id}/{role_id}"
        log.info(f"Deleting user-role assignment | Endpoint: {endpoint}")
        try:
            resp = self.delete(endpoint, token=token)
            log.info(f"Delete user-role assignment response | Status: {resp.status_code}")
            return resp.status_code
        except Exception as e:
            log.error(f"Failed to delete user-role assignment: {e}")
            raise

    def list_user_roles(self, token: str, page: int = 1, page_size: int = 20):
        """
        Retrieve a paginated list of all user-role assignments.
        """
        endpoint = f"/api/{self.api_version}/management/user-roles"
        params = {"page": page, "page_size": page_size}
        log.info(f"Fetching user-role assignments list | Endpoint: {endpoint} | Params: {params}")
        try:
            resp = self.get(endpoint, token=token, params=params)
            log.info(f"List user roles response | Status: {resp.status_code}")
            return resp.json()
        except Exception as e:
            log.error(f"Failed to list user roles: {e}")
            raise

    def get_audit_log_by_id(self, token: str, log_id: str):
        """
        Retrieve a single audit log entry by its unique ID.
        """
        endpoint = f"/api/{self.api_version}/management/audit-log/{log_id}"
        log.info(f"Fetching audit log by ID | Endpoint: {endpoint}")
        try:
            resp = self.get(endpoint, token=token)
            log.info(f"Get audit log response | Status: {resp.status_code}")
            return resp.json()
        except Exception as e:
            log.error(f"Failed to fetch audit log by ID: {e}")
            raise

    def list_audit_logs(self, token: str, params: dict = None):
        """
        Fetch paginated audit logs with optional filters.
        """
        endpoint = f"/api/{self.api_version}/management/audit-logs"
        log.info(f"Fetching audit logs list | Endpoint: {endpoint} | Params: {params}")
        try:
            resp = self.get(endpoint, token=token, params=params)
            log.info(f"List audit logs response | Status: {resp.status_code}")
            return resp.json()
        except Exception as e:
            log.error(f"Failed to list audit logs: {e}")
            raise

    def create_gym(self, token: str, gym_payload: dict):
        """
        Create a new gym.
        """
        endpoint = f"/api/{self.api_version}/management/gym"
        log.info(f"Creating gym | Endpoint: {endpoint} | Payload: {gym_payload}")
        try:
            resp = self.post(endpoint, token=token, json=gym_payload)
            log.info(f"Create gym response | Status: {resp.status_code}")
            return resp.json()
        except Exception as e:
            log.error(f"Failed to create gym: {e}")
            raise

    def get_gym_by_id(self, token: str, gym_id: str):
        """
        Fetch a gym by its ID.
        """
        endpoint = f"/api/{self.api_version}/management/gym/{gym_id}"
        log.info(f"Fetching gym by ID | Endpoint: {endpoint}")
        try:
            resp = self.get(endpoint, token=token)
            log.info(f"Get gym by ID response | Status: {resp.status_code}")
            return resp.json()
        except Exception as e:
            log.error(f"Failed to fetch gym by ID: {e}")
            raise

    def update_gym(self, token: str, gym_id: str, payload: dict):
        """
        Update a gym by ID.
        """
        endpoint = f"/api/{self.api_version}/management/gym/{gym_id}"
        log.info(f"Updating gym | Endpoint: {endpoint} | Payload: {payload}")
        try:
            resp = self.put(endpoint, token=token, json=payload)
            log.info(f"Update gym response | Status: {resp.status_code}")
            return resp.json()
        except Exception as e:
            log.error(f"Failed to update gym: {e}")
            raise

    def delete_gym(self, token: str, gym_id: str):
        """
        Delete a gym by its UUID.
        """
        endpoint = f"/api/{self.api_version}/management/gym/{gym_id}"
        log.info(f"Deleting gym | Endpoint: {endpoint}")
        try:
            resp = self.delete(endpoint, token=token)
            log.info(f"Delete gym response | Status: {resp.status_code}")
            return resp.status_code
        except Exception as e:
            log.error(f"Failed to delete gym: {e}")
            raise

    def list_gyms(self, token: str, params: dict = None):
        """
        Retrieve all gyms with optional filters.
        """
        endpoint = f"/api/{self.api_version}/management/gyms"
        log.info(f"Fetching gyms list | Endpoint: {endpoint} | Params: {params}")
        try:
            resp = self.get(endpoint, token=token, params=params)
            log.info(f"List gyms response | Status: {resp.status_code}")
            return resp.json()
        except Exception as e:
            log.error(f"Failed to list gyms: {e}")
            raise

    def invite_user_to_gym(self, token: str, gym_id: str, user_id: str):
        """
        Invite a user to a specific gym.
        """
        endpoint = f"/api/{self.api_version}/management/gym/{gym_id}/invite"
        payload = {"user_id": user_id}
        log.info(f"Inviting user to gym | Endpoint: {endpoint} | Payload: {payload}")
        try:
            resp = self.post(endpoint, token=token, json=payload)
            log.info(f"Invite user response | Status: {resp.status_code}")
            return resp.json()
        except Exception as e:
            log.error(f"Failed to invite user to gym: {e}")
            raise

    def list_users_for_gym(self, token: str, gym_id: str):
        """
        Retrieve users invited to a specific gym.
        """
        endpoint = f"/api/{self.api_version}/management/gym/{gym_id}/users"
        log.info(f"Fetching users for gym | Endpoint: {endpoint}")
        try:
            resp = self.get(endpoint, token=token)
            log.info(f"List users for gym response | Status: {resp.status_code}")
            return resp.json()
        except Exception as e:
            log.error(f"Failed to list users for gym: {e}")
            raise

    def remove_user_from_gym(self, token: str, gym_id: str, user_id: str):
        """
        Revoke a user's access to a gym.
        """
        endpoint = f"/api/{self.api_version}/management/gym/{gym_id}/users/{user_id}"
        log.info(f"Removing user from gym | Endpoint: {endpoint}")
        try:
            resp = self.delete(endpoint, token=token)
            log.info(f"Remove user response | Status: {resp.status_code}")
            return resp.status_code
        except Exception as e:
            log.error(f"Failed to remove user from gym: {e}")
            raise

    def create_gym_user(self, user_data: dict):
        """
        Register a new gym user.
        """
        endpoint = f"/api/{self.api_version}/gym/auth/register"
        log.info(f"Registering gym user | Endpoint: {endpoint} | Payload: {user_data}")
        try:
            resp = self.post(endpoint, json=user_data)
            log.info(f"Create gym user response | Status: {resp.status_code}")
            return resp
        except Exception as e:
            log.error(f"Failed to create gym user: {e}")
            raise

    def verify_gym_email(self, token: str):
        """
        Verify gym user email using a token.
        """
        endpoint = f"/api/{self.api_version}/gym/auth/verify-email"
        params = {"token": token}
        log.info(f"Verifying gym user email | Endpoint: {endpoint} | Params: {params}")
        try:
            resp = self.get(endpoint, params=params)
            log.info(f"Verify gym email response")
            return resp
        except Exception as e:
            log.error(f"Failed to verify gym email: {e}")
            raise

    def resend_verification_email(self, email: str):
        """
        Resend email verification link to a gym user.
        """
        endpoint = f"/api/{self.api_version}/gym/auth/resend-verification"
        payload = {"email": email}
        log.info(f"Resending verification email | Endpoint: {endpoint} | Payload: {payload}")
        try:
            resp = self.post(endpoint, json=payload)
            log.info(f"Resend verification email response | Status: {resp.status_code}")
            return
        except Exception as e:
            log.error(f"Failed to resend verification email: {e}")
            raise

    def request_password_reset(self, email: str):
        """
        Request a password reset for a gym user.
        """
        endpoint = f"/api/{self.api_version}/gym/auth/forgot-password"
        payload = {"email": email}
        log.info(f"Requesting password reset | Endpoint: {endpoint} | Payload: {payload}")
        try:
            resp = self.post(endpoint, json=payload)
            log.info(f"Password reset request response | Status: {resp.status_code}")
            return resp
        except Exception as e:
            log.error(f"Failed to request password reset: {e}")
            raise

    def reset_gym_password(self, token: str, password: str, cpassword: str):
        """
        Reset gym user password using a token.
        """
        endpoint = f"/api/{self.api_version}/gym/auth/password-reset"
        params = {"token": token}
        payload = {"password": password, "cpassword": cpassword}
        log.info(f"Resetting gym password | Endpoint: {endpoint} | Params: {params} | Payload: {payload}")
        try:
            resp = self.post(endpoint, params=params, json=payload)
            log.info(f"Reset gym password response | Status: {resp.status_code}")
            return resp.json()
        except Exception as e:
            log.error(f"Failed to reset gym password: {e}")
            raise

    def login_gym_user(self, email: str, password: str):
        """
        Log in a gym user.

        Args:
            email (str): Gym user's email.
            password (str): Gym user's password.

        Returns:
            dict: API response as JSON.
        """
        endpoint = f"/api/{self.api_version}/gym/auth/login"
        payload = {"email": email, "password": "[PROTECTED]"}
        log.info(f"Logging in gym user | Endpoint: {endpoint} | Email: {email}")
        try:
            resp = self.post(endpoint, json={"email": email, "password": password})
            log.info(f"Gym user login response | Status: {resp.status_code}")
            return resp.json()
        except Exception as e:
            log.error(f"Failed to log in gym user: {e}")
            raise

    def refresh_gym_token(self, refresh_token: str):
        """
        Refresh gym user's access token.

        Args:
            refresh_token (str): Refresh token.

        Returns:
            dict: API response as JSON.
        """
        endpoint = f"/api/{self.api_version}/gym/auth/refresh"
        log.info(f"Refreshing gym access token | Endpoint: {endpoint}")
        try:
            resp = self.post(endpoint, json={"refresh_token": refresh_token})
            log.info(f"Refresh token response | Status: {resp.status_code}")
            return resp.json()
        except Exception as e:
            log.error(f"Failed to refresh gym token: {e}")
            raise

    def gym_logout(self, token: str):
        """
        Log out a gym user.

        Args:
            token (str): Bearer JWT access token.

        Returns:
            int: HTTP status code.
        """
        endpoint = f"/api/{self.api_version}/gym/auth/logout"
        log.info(f"Logging out gym user | Endpoint: {endpoint}")
        try:
            resp = self.get(endpoint, token=token)
            log.info(f"Gym user logout response: {resp}")
            return resp

        except Exception as e:
            log.error(f"Failed to log out gym user: {e}")
            raise

    def get_gym_user_profile(self, token: str):
        """
        Retrieve the currently authenticated gym user's profile.
        """
        endpoint = f"/api/{self.api_version}/gym/user/me"
        log.info("Fetching gym user profile")
        try:
            resp = self.get(endpoint, token=token)
            log.info("Profile fetched successfully")
            return resp.json()
        except Exception as e:
            log.error(f"Get gym user profile failed: {e}")
            raise

    def get_gym_user_by_id(self, token: str, user_id: str):
        """
        Retrieve a gym user by their unique ID.
        """
        endpoint = f"/api/{self.api_version}/gym/user/{user_id}"
        log.info("Fetching gym user by ID")
        try:
            resp = self.get(endpoint, token=token)
            log.info("Gym user fetched successfully")
            return resp.json()
        except Exception as e:
            log.error(f"Get gym user by ID failed: {e}")
            raise

    def update_gym_user_by_id(self, token: str, user_id: str, payload: dict):
        """
        Update a gym user by their unique ID.
        """
        endpoint = f"/api/{self.api_version}/gym/user/{user_id}"
        log.info("Updating gym user")
        try:
            resp = self.put(endpoint, token=token, json=payload)
            log.info("Gym user updated successfully")
            return resp.json()
        except Exception as e:
            log.error(f"Update gym user failed: {e}")
            raise

    def delete_gym_user(self, token: str, user_id: str):
        """
        Delete a gym user by their unique ID.
        """
        endpoint = f"/api/{self.api_version}/gym/user/{user_id}"
        log.info("Deleting gym user")
        try:
            resp = self.delete(endpoint, token=token)
            log.info("Gym user deleted successfully")
            return resp.status_code
        except Exception as e:
            log.error(f"Delete gym user failed: {e}")
            raise

    def list_gym_users(self, token: str, params: dict = None):
        """
        Retrieve a list of gym users with optional filters.
        """
        endpoint = f"/api/{self.api_version}/gym/users"
        log.info("Listing gym users")
        try:
            resp = self.get(endpoint, token=token, params=params)
            log.info("Gym users listed successfully")
            return resp.json()
        except Exception as e:
            log.error(f"List gym users failed: {e}")
            raise

    def assign_gym_user_role(self, token: str, user_id: str, role_id: str):
        """
        Assign a role to a gym user.
        """
        endpoint = f"/api/{self.api_version}/gym/user-role"
        log.info("Assigning role to gym user")
        try:
            resp = self.post(endpoint, token=token, json={"user_id": user_id, "role_id": role_id})
            log.info("Role assigned successfully")
            return resp.json()
        except Exception as e:
            log.error(f"Assign gym user role failed: {e}")
            raise

    def get_gym_user_role(self, token: str, user_id: str, role_id: str):
        """
        Retrieve a gym user's role assignment.
        """
        endpoint = f"/api/{self.api_version}/gym/user-role/{user_id}/{role_id}"
        log.info("Fetching gym user role")
        try:
            resp = self.get(endpoint, token=token)
            log.info("Gym user role fetched successfully")
            return resp.json()
        except Exception as e:
            log.error(f"Get gym user role failed: {e}")
            raise

    def update_gym_user_role(self, token: str, user_id: str, role_id: str, update_data: dict):
        """
        Update a gym user's role assignment.
        """
        endpoint = f"/api/{self.api_version}/gym/user-role/{user_id}/{role_id}"
        log.info("Updating gym user role")
        try:
            resp = self.put(endpoint, token=token, json=update_data)
            log.info("Gym user role updated successfully")
            return resp.json()
        except Exception as e:
            log.error(f"Update gym user role failed: {e}")
            raise

    def delete_gym_user_role(self, token: str, user_id: str, role_id: str):
        """
        Delete a gym user's role assignment.
        """
        endpoint = f"/api/{self.api_version}/gym/user-role/{user_id}/{role_id}"
        log.info("Deleting gym user role")
        try:
            resp = self.delete(endpoint, token=token)
            log.info("Gym user role deleted successfully")
            return resp.status_code
        except Exception as e:
            log.error(f"Delete gym user role failed: {e}")
            raise

    def list_gym_user_roles(self, token: str, params: dict = None):
        """
        Retrieve all gym user-role assignments.
        """
        endpoint = f"/api/{self.api_version}/gym/user-roles"
        log.info("Listing gym user roles")
        try:
            resp = self.get(endpoint, token=token, params=params)
            log.info("Gym user roles listed successfully")
            return resp.json()
        except Exception as e:
            log.error(f"List gym user roles failed: {e}")
            raise
