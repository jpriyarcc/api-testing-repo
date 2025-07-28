from typing import Optional

import requests

import requests
from utils.api_data import ManagementUserCreate, AuditLogResponse,PaginatedAPIResponseAuditLog

import logging

log = logging.getLogger(__name__)


class ManagementUserAPIHandler:
    def __init__(self, base_url: str, api_version: str = "v1"):
        self.base_url = base_url.rstrip("/")
        self.api_version = api_version

    def register_user(self, user: ManagementUserCreate, timeout: int = 10):
        endpoint = f"{self.base_url}/api/{self.api_version}/management/auth/register"
        payload = user.to_dict()
        resp = requests.post(endpoint, json=payload, timeout=timeout)
        resp.raise_for_status()
        return resp

    def verify_email(self, token: str) -> requests.Response:
        """
        Verify management user email with the given token.
        """
        url = f"{self.base_url}/api/v1/management/auth/verify-email"
        params = {"token": token}
        resp = requests.get(url, params=params)
        return resp

    def resend_verification(self, email: str) -> requests.Response:
        """
        Resend email verification link to the given email.
        """
        url = f"{self.base_url}/api/v1/management/auth/resend-verification"
        payload = {"email": email}
        resp = requests.post(url, json=payload)
        return resp

    def forgot_password(self, email: str) -> requests.Response:
        """
        Request a password reset link to the given email.
        """
        url = f"{self.base_url}/api/v1/management/auth/forgot-password"
        payload = {"email": email}
        resp = requests.post(url, json=payload)
        return resp

    def reset_password(self, token: str, password: str, cpassword: str) -> requests.Response:
        url = f"{self.base_url}/api/v1/management/auth/password-reset"
        params = {"token": token}
        payload = {
            "password": password,
            "cpassword": cpassword,
        }
        resp = requests.post(url, params=params, json=payload)
        return resp

    def login(self, email: str, password: str) -> requests.Response:
        """
        Perform login with given credentials.
        """
        url = f"{self.base_url}/api/v1/management/auth/login"
        payload = {
            "email": email,
            "password": password
        }
        resp = requests.post(url, json=payload)
        return resp

    def refresh_token(self, refresh_token):
        return requests.post(f"{self.base_url}/refresh", headers={"Authorization": f"Bearer {refresh_token}"})

    def logout_user(self, token: str) -> requests.Response:
        """
        Logs out the user.

        Args:
            token (str): Bearer token of the logged-in user.

        Returns:
            requests.Response: Response object from the logout API.
        """
        url = f"{self.base_url}/api/v1/management/auth/logout"
        headers = {
            "Authorization": f"Bearer {token}"
        }
        response = requests.get(url, headers=headers)
        return response

    def get_current_user(self, token: str) -> requests.Response:
        """
        Get details of the currently logged-in user.

        Args:
            token (str): Bearer token.

        Returns:
            requests.Response: Response from the API.
        """
        url = f"{self.base_url}/api/v1/management/user/me"
        headers = {
            "Authorization": f"Bearer {token}"
        }
        response = requests.get(url, headers=headers)
        return response

    def get_user_by_id(self, user_id: str, token: str):
        """

        Args:
            user_id:
            token:

        Returns:

        """
        log.info(f"user: {user_id}{token}")

        url = f"{self.base_url}/api/v1/management/user/{user_id}"
        headers = {
            "Authorization": f"Bearer {token}"
        }
        response = requests.get(url, headers=headers)
        return response

    def update_user_by_id(self, user_id: str, token: str, update_payload: dict):
        """
        Update a management user's details by ID.
        Args:
            user_id: UUID of the user to update
            token: Bearer token for authentication
            update_payload: dict of fields to update
        Returns:
            requests.Response
        """
        url = f"{self.base_url}/api/v1/management/user/{user_id}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        response = requests.put(url, headers=headers, json=update_payload)
        return response

    def delete_user_by_id(self, user_id: str, token: str):
        """
        Deletes a management user by ID.
        Args:
            user_id (str): UUID of the user.
            token (str): Bearer token.
        Returns:
            Response: requests.Response object.
        """
        url = f"{self.base_url}/api/v1/management/user/{user_id}"
        headers = {
            "Authorization": f"Bearer {token}"
        }
        response = requests.delete(url, headers=headers)
        return response

    def list_management_users(self, token: str, params: dict = None):
        """
        Retrieves a paginated list of management users, with optional filters.

        Args:
            token (str): Bearer JWT token.
            params (dict): Optional query parameters.

        Returns:
            Response: requests.Response object
        """
        log.info(f"token: {token}")
        url = f"{self.base_url}/api/v1/management/users"
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(url, headers=headers, params=params)
        return response

    def create_role(self, token: str, role_data: dict):
        """
        Create a new management role.

        Args:
            token (str): Bearer JWT token.
            role_data (dict): Payload for creating the role.

        Returns:
            requests.Response: HTTP response object.
        """
        url = f"{self.base_url}/api/v1/management/role"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        response = requests.post(url, headers=headers, json=role_data)
        return response

    def get_role_by_id(self, token: str, role_id: str):
        """
        Get a management role by UUID.

        Args:
            token (str): Bearer JWT token.
            role_id (str): UUID of the role.

        Returns:
            requests.Response: HTTP response object.
        """
        url = f"{self.base_url}/api/v1/management/role/{role_id}"
        headers = {
            "Authorization": f"Bearer {token}"
        }
        response = requests.get(url, headers=headers)
        return response

    def update_role_by_id(self, token: str, role_id: str, update_data: dict):
        """
        Update a management role by ID.

        Args:
            token (str): Bearer token for auth
            role_id (str): UUID of role
            update_data (dict): role update payload

        Returns:
            requests.Response: API response
        """
        url = f"{self.base_url}/api/v1/management/role/{role_id}"
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.put(url, headers=headers, json=update_data)
        return response

    def delete_role_by_id(self, token: str, role_id: str):
        """

        Args:
            token:
            role_id:

        Returns:

        """
        url = f"{self.base_url}/api/v1/management/role/{role_id}"
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.delete(url, headers=headers)
        return response

    def list_roles(self, token: str, page: int = 1, page_size: int = 20):
        """
        Retrieves a paginated list of management roles.

        Args:
            token (str): Bearer token for authorization
            page (int): Page number
            page_size (int): Number of items per page

        Returns:
            Response object
        """
        url = f"{self.base_url}/api/v1/management/roles"
        headers = {
            "Authorization": f"Bearer {token}"
        }
        params = {
            "page": page,
            "page_size": page_size
        }
        response = requests.get(url, headers=headers, params=params)
        return response

    def assign_permission_to_role(self, token: str, payload: dict):
        """
        Assigns a permission to a role.

        Args:
            token (str): Bearer token for authorization
            payload (dict): request body containing role and permission info

        Returns:
            Response object
        """
        url = f"{self.base_url}/api/v1/management/role-permission"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        response = requests.post(url, headers=headers, json=payload)
        return response

    def get_role_permission(self, token: str, role_id: str, permission_id: str):
        """
        Get a role-permission assignment.

        Args:
            token (str): Bearer token
            role_id (str): Role UUID
            permission_id (str): Permission UUID

        Returns:
            Response object
        """
        url = f"{self.base_url}/api/v1/management/role-permission/{role_id}/{permission_id}"
        headers = {
            "Authorization": f"Bearer {token}"
        }
        response = requests.get(url, headers=headers)
        return response

    def update_role_permission(self, token: str, role_id: str, permission_id: str, update_data: dict):
        """
        Update a role-permission assignment.

        Args:
            token (str): Bearer token
            role_id (str): Role UUID
            permission_id (str): Permission UUID
            update_data (dict): Update payload

        Returns:
            Response object
        """
        url = f"{self.base_url}/api/v1/management/role-permission/{role_id}/{permission_id}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        response = requests.put(url, headers=headers, json=update_data)
        return response

    def delete_role_permission(self, token: str, role_id: str, permission_id: str):
        """
        Delete a role-permission assignment.

        Args:
            token (str): Bearer token
            role_id (str): Role UUID
            permission_id (str): Permission UUID

        Returns:
            Response object
        """
        url = f"{self.base_url}/api/v1/management/role-permission/{role_id}/{permission_id}"
        headers = {
            "Authorization": f"Bearer {token}"
        }
        response = requests.delete(url, headers=headers)
        return response

    def list_role_permissions(self, token: str, page: int = 1, page_size: int = 20):
        """
        List all role-permission assignments (paginated).

        Args:
            token (str): Bearer token
            page (int): page number
            page_size (int): page size

        Returns:
            requests.Response
        """
        url = f"{self.base_url}/api/v1/management/role-permissions"
        headers = {"Authorization": f"Bearer {token}"}
        params = {
            "page": page,
            "page_size": page_size
        }
        return requests.get(url, headers=headers, params=params)

    def create_permission(self, token: str, payload: dict):
        """
        Create a new management permission.

        Args:
            token (str): Bearer token
            payload (dict): JSON body with permission details

        Returns:
            requests.Response
        """
        url = f"{self.base_url}/api/v1/management/permission"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        return requests.post(url, headers=headers, json=payload)

    def get_permission_by_id(self, token: str, permission_id: str):
        """
        Retrieve a management permission by ID.

        Args:
            token (str): Bearer token
            permission_id (str): UUID of the permission

        Returns:
            dict: JSON response
            int: HTTP status code
        """
        url = f"{self.base_url}/api/v1/management/permission/{permission_id}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        response = requests.get(url, headers=headers)

        # Return JSON and status code
        try:
            json_data = response.json()
        except ValueError:
            json_data = None  # in case of 204 or bad response

        return json_data, response.status_code

    def update_permission_by_id(self, token: str, permission_id: str, update_data: dict):
        """
        Update a management permission by ID.

        Args:
            token (str): Bearer token
            permission_id (str): UUID of the permission
            update_data (dict): Payload to update (code, description, group_id)

        Returns:
            tuple: (json_response: dict or None, status_code: int)
        """
        url = f"{self.base_url}/api/v1/management/permission/{permission_id}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        response = requests.put(url, headers=headers, json=update_data)

        try:
            json_data = response.json()
        except ValueError:
            json_data = None

        return json_data, response.status_code

    def delete_permission_by_id(self, token: str, permission_id: str) -> int:
        """
        Deletes a management permission by its ID.

        Args:
            token (str): Bearer token.
            permission_id (str): UUID of the permission.

        Returns:
            int: HTTP status code (e.g., 204, 404, 500, 422).
        """
        url = f"{self.base_url}/api/v1/management/permission/{permission_id}"
        headers = {
            "Authorization": f"Bearer {token}"
        }
        response = requests.delete(url, headers=headers)
        return response.status_code

    def list_permissions(self, token: str, page: int = 1, page_size: int = 20):
        """
        Get a paginated list of all management permissions.

        Args:
            token (str): Bearer token
            page (int): Page number (default: 1)
            page_size (int): Page size (default: 20)

        Returns:
            dict: JSON response
            int: HTTP status code
        """
        url = f"{self.base_url}/api/v1/management/permissions"
        headers = {
            "Authorization": f"Bearer {token}"
        }
        params = {
            "page": page,
            "page_size": page_size
        }

        response = requests.get(url, headers=headers, params=params)

        try:
            json_data = response.json()
        except ValueError:
            json_data = None

        return json_data, response.status_code

    def create_permission_group(self, token: str, payload: dict):
        """
        Create a new management permission group.

        Args:
            token (str): Bearer token
            payload (dict): JSON body with group details

        Returns:
            requests.Response
        """
        url = f"{self.base_url}/api/v1/management/permission-group"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        response = requests.post(url, headers=headers, json=payload)
        return response

    def get_permission_group_by_id(self, token: str, group_id: str):
        """
        Retrieve a management permission group by ID.

        Args:
            token (str): Bearer token
            group_id (str): UUID of the permission group

        Returns:
            tuple: (json_data: dict or None, status_code: int)
        """
        url = f"{self.base_url}/api/v1/management/permission-group/{group_id}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        response = requests.get(url, headers=headers)

        try:
            json_data = response.json()
        except ValueError:
            json_data = None  # In case of empty or invalid response

        return json_data, response.status_code

    def get_permission_group(self, token: str, group_id: str, timeout: int = 10) -> requests.Response:
        url = f"{self.base_url}/api/v1/management/permission-group/{group_id}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json"
        }
        return requests.get(url, headers=headers, timeout=timeout)

    def update_permission_group(
            self,
            token: str,
            group_id: str,
            name: Optional[str] = None,
            code: Optional[str] = None,
            description: Optional[str] = None,
            timeout: int = 10
    ) -> requests.Response:
        url = f"{self.base_url}/api/v1/management/permission-group/{group_id}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        payload = {k: v for k, v in {
            "name": name,
            "code": code,
            "description": description
        }.items() if v is not None}
        return requests.put(url, headers=headers, json=payload, timeout=timeout)

    def delete_permission_group(self, token: str, group_id: str, timeout: int = 10) -> requests.Response:
        url = f"{self.base_url}/api/v1/management/permission-group/{group_id}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json"
        }
        return requests.delete(url, headers=headers, timeout=timeout)

    def get_permissions(self, token: str, page: int = 1, page_size: int = 20):
        """
        Fetch management permissions with optional pagination and token.

        Args:

            token (str): Bearer token.
            page (int): Page number (default=1).
            page_size (int): Number of items per page (default=20).

        Returns:
            Tuple of (status_code, response_json)
        """
        url = f"{self.base_url}/api/v1/management/permissions"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }
        params = {"page": page, "page_size": page_size}

        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            return response.status_code, response.json()
        except requests.exceptions.HTTPError as e:
            response = e.response
            return response.status_code, response.json()
        except requests.exceptions.RequestException as e:
            return 500, {"message": str(e), "success": False}

    def create_management_permission(self, token: str, permission_data: dict) -> requests.Response:
        """
        Create a new management permission.

        Args:
            token (str): Bearer token for authorization.
            permission_data (dict): Dictionary containing permission details.

        Returns:
            requests.Response: Response object from the POST request.
        """
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        url = f"{self.base_url}/api/v1/management/permission"
        return requests.post(url, json=permission_data, headers=headers)

    def get_management_permission_by_id(self, token: str, permission_id: str) -> requests.Response:
        """
        Fetch a management permission by its ID.

        Args:
            token (str): Bearer token.
            permission_id (str): UUID of the permission to retrieve.

        Returns:
            requests.Response: API response object.
        """
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json"
        }

        url = f"{self.base_url}/api/v1/management/permission/{permission_id}"
        return requests.get(url, headers=headers)

    def update_permission(self, token: str, permission_id: str, update_data: dict):
        """
        Updates an existing management permission.
        """
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        url = f"{self.base_url}/api/v1/management/permission/{permission_id}"
        response = requests.put(url, json=update_data, headers=headers)
        log.info(f"[PUT] {url}")
        log.info(f"Request Body: {update_data}")
        log.info(f"Response Status: {response.status_code}")
        log.info(f"Response Body: {response.text}")
        return response

    def delete_permission(self, token: str, permission_id: str):
        """
        Delete a management permission by UUID.
        """
        url = f"{self.base_url}/api/v1/management/permission/{permission_id}"

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        response = requests.delete(url, headers=headers)

        log.info(f"[DELETE] {url}")
        log.info(f"Status Code: {response.status_code}")
        log.info(f"Response Body: {response.text if response.content else 'No content'}")
        return response

    def list_management_permissions(self, token: str, page: int = 1, page_size: int = 20):
        """
        List all management permissions (paginated).
        """
        url = f"{self.base_url}/api/v1/management/permissions"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        params = {
            "page": page,
            "page_size": page_size
        }

        response = requests.get(url, headers=headers, params=params)

        log.info(f"[GET] {url} | Params: {params}")
        log.info(f"Status Code: {response.status_code}")
        log.info(f"Response: {response.text if response.content else 'No content'}")

        return response

    def create_management_permission_group(self, token: str, group_data: dict):
        """
        Create a new management permission group.

        Args:
            token (str): Bearer token for authorization
            group_data (dict): The JSON body to create permission group.

        Returns:
            Response object
        """
        url = f"{self.base_url}/api/v1/management/permission-group"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        log.info(f"[POST] {url} | Payload: {group_data}")

        response = requests.post(url, headers=headers, json=group_data)

        log.info(f"Status Code: {response.status_code}")
        log.info(f"Response Body: {response.text if response.content else 'No content'}")

        return response

    def get_management_permission_group(self, token: str, group_id: str) -> requests.Response:
        """
        Retrieve a specific permission group by its UUID.

        Args:
            token (str): Bearer token for authorization
            group_id (str): UUID of the permission group

        Returns:
            Response object
        """
        url = f"{self.base_url}/api/v1/management/permission-group/{group_id}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        log.info(f"[GET] {url}")

        response = requests.get(url, headers=headers)
        log.info(f"Status Code: {response.status_code}")
        log.info(f"Response Body: {response.text if response.content else 'No content'}")
        return response

    def update_management_permission_group(self, token: str, group_id: str, update_data: dict) -> requests.Response:
        """
        Update an existing permission group by its UUID.

        Args:
            self:
            token (str): Bearer token for authorization
            group_id (str): UUID of the permission group to update
            update_data (dict): Fields to update (name, code, description)

        Returns:
            Response object
        """
        url = f"{self.base_url}/api/v1/management/permission-group/{group_id}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        log.info(f"[PUT] {url} | Data: {update_data}")

        response = requests.put(url, headers=headers, json=update_data)

        log.info(f"Status Code: {response.status_code}")
        log.info(f"Response Body: {response.text if response.content else 'No content'}")
        return response

    def delete_management_permission_group(self, token: str, group_id: str) -> requests.Response:
        """
        Delete a permission group by its UUID.

        Args:
            token (str): Bearer token for authorization
            group_id (str): UUID of the permission group to delete

        Returns:
            requests.Response: HTTP response object
        """
        url = f"{self.base_url}/api/v1/management/permission-group/{group_id}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        log.info(f"[DELETE] {url}")
        response = requests.delete(url, headers=headers)
        log.info(f"Status Code: {response.status_code}")
        log.info(f"Response Body: {response.text if response.content else 'No content'}")

        return response

    def list_permission_groups(self, token: str, page: int = 1, page_size: int = 20) -> requests.Response:
        """
        Retrieve a paginated list of all permission groups.

        Args:
            token (str): Bearer token for authorization.
            page (int): Page number.
            page_size (int): Number of items per page.

        Returns:
            Response object from requests
        """
        url = f"{self.base_url}/api/v1/management/permission-groups"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        params = {
            "page": page,
            "page_size": page_size
        }

        log.info(f"[GET] {url} | Params: {params}")
        response = requests.get(url, headers=headers, params=params)
        log.info(f"Status Code: {response.status_code}")
        log.info(f"Response Body: {response.text if response.content else 'No content'}")
        return response

    def assign_user_role(self, token: str, payload: dict) -> requests.Response:
        """
        Assigns a role to a user.

        Args:
            token (str): Bearer token for authorization.
            payload (dict): Role assignment details.

        Returns:
            Response object from requests.
        """
        url = f"{self.base_url}/api/v1/management/user-role"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        log.info(f"[POST] {url} | Payload: {payload}")
        response = requests.post(url, headers=headers, json=payload)
        log.info(f"Status Code: {response.status_code}")
        log.info(f"Response Body: {response.text if response.content else 'No content'}")
        return response

    def get_user_role_assignment(self, token: str, user_id: str, role_id: str) -> requests.Response:
        """
        Retrieves a specific user-role assignment by user ID and role ID.

        Args:
            token (str): Bearer token for authorization.
            user_id (str): UUID of the user.
            role_id (str): UUID of the role.

        Returns:
            requests.Response: Response object
        """
        url = f"{self.base_url}/api/v1/management/user-role/{user_id}/{role_id}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        log.info(f"[GET] {url}")
        response = requests.get(url, headers=headers)
        log.info(f"Status Code: {response.status_code}")
        log.info(f"Response Body: {response.text if response.content else 'No content'}")
        return response

    def update_user_role_assignment(self, token: str, user_id: str, role_id: str,
                                    update_data: dict) -> requests.Response:
        """
        Updates an existing user-role assignment.

        Args:
            token (str): Bearer token for authorization.
            user_id (str): UUID of the user (path param).
            role_id (str): UUID of the role (path param).
            update_data (dict): JSON body with user_id and/or role_id fields to update.

        Returns:
            requests.Response: Response object
        """
        url = f"{self.base_url}/api/v1/management/user-role/{user_id}/{role_id}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        log.info(f"[PUT] {url} - Payload: {update_data}")
        response = requests.put(url, headers=headers, json=update_data)
        log.info(f"Status Code: {response.status_code}")
        log.info(f"Response Body: {response.text if response.content else 'No content'}")
        return response

    def delete_user_role_assignment(self, token: str, user_id: str, role_id: str) -> requests.Response:
        """
        Deletes a user-role assignment by user ID and role ID.

        Args:
            token (str): Bearer token for authentication.
            user_id (str): UUID of the user.
            role_id (str): UUID of the role.

        Returns:
            requests.Response: HTTP response object.
        """
        url = f"{self.base_url}/api/v1/management/user-role/{user_id}/{role_id}"
        headers = {
            "Authorization": f"Bearer {token}",
        }
        log.info(f"[DELETE] {url}")
        response = requests.delete(url, headers=headers)
        log.info(f"Status Code: {response.status_code}")
        log.info(f"Response Body: {response.text if response.content else 'No content'}")
        return response

    def list_user_roles(self, token: str, page: int = 1, page_size: int = 20) -> requests.Response:
        """
        Retrieves a paginated list of all user-role assignments.

        Args:
            token (str): Bearer token for authentication.
            page (int, optional): Page number. Defaults to 1.
            page_size (int, optional): Number of items per page. Defaults to 20.

        Returns:
            requests.Response: HTTP response object.
        """
        url = f"{self.base_url}/api/v1/management/user-roles"
        headers = {
            "Authorization": f"Bearer {token}",
        }
        params = {
            "page": page,
            "page_size": page_size
        }
        log.info(f"[GET] {url} with params {params}")
        response = requests.get(url, headers=headers, params=params)
        log.info(f"Status Code: {response.status_code}")
        log.info(f"Response Body: {response.text if response.content else 'No content'}")
        return response

    def get_audit_log_by_id(self, token: str, log_id: str) -> requests.Response:
        """
        Retrieves a single audit log entry by its unique ID.

        Args:
            token (str): Bearer token for authentication.
            log_id (str): UUID of the audit log entry.

        Returns:
            requests.Response: HTTP response object.
        """
        url = f"{self.base_url}/api/v1/management/audit-log/{log_id}"
        headers = {
            "Authorization": f"Bearer {token}",
        }
        log.info(f"[GET] {url}")
        response = requests.get(url, headers=headers)
        log.info(f"Status Code: {response.status_code}")
        log.info(f"Response Body: {response.text if response.content else 'No content'}")
        return response

    def list_audit_logs(
            api_url: str,
            token: str,
            **filters  # Accepts optional filters as kwargs
    ) -> PaginatedAPIResponseAuditLog:
        """
        Fetches paginated audit logs and parses into dataclasses.

        Parameters:
          - api_url: API endpoint URL
          - token: Bearer token for auth
          - filters: Optional query parameters like user_id, method, path, limit, offset, etc.

        Returns:
          - PaginatedAPIResponseAuditLog dataclass instance
        """
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json"
        }

        response = requests.get(api_url, headers=headers, params=filters)
        response.raise_for_status()
        json_data = response.json()

        audit_logs = [AuditLogResponse(**item) for item in json_data["data"]]

        paginated_response = PaginatedAPIResponseAuditLog(
            status=json_data["status"],
            message=json_data["message"],
            data=audit_logs,
            total=json_data["total"],
            page=json_data["page"],
            page_size=json_data["page_size"],
            total_pages=json_data["total_pages"]
        )

        return paginated_response

    def create_gym(self, gym_payload: dict, token: str) -> dict:
        """
        Creates a new gym.

        Parameters:
        - gym_payload: dict containing gym creation data
        - token: string, Bearer token for authorization

        Returns:
        - dict response from API
        """
        url = f"{self.base_url}/api/v1/management/gym"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        response = requests.post(url, headers=headers, json=gym_payload)
        response.raise_for_status()
        return response.json()

    def get_gym_by_id(self, token: str, gym_id: str):
        """
        GET /api/v1/management/gym/{gym_id} - Fetch gym by ID

        Args:
            token (str): Bearer auth token
            gym_id (str): UUID of the gym

        Returns:
            requests.Response
        """
        url = f"{self.base_url}/api/v1/management/gym/{gym_id}"
        headers = {
            "Authorization": f"Bearer {token}"
        }

        response = requests.get(url, headers=headers)
        return response  # Return the full response object

    def update_gym(self, token: str, gym_id: str, payload: dict):
        """
        Update a gym by ID using the provided payload.
        Returns: requests.Response
        """
        url = f"{self.base_url}/api/v1/management/gym/{gym_id}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        response = requests.put(url, json=payload, headers=headers)
        return response

    def delete_gym(self, token: str, gym_id: str):
        """
        Deletes a gym by its UUID.
        Returns: requests.Response
        """
        url = f"{self.base_url}/api/v1/management/gym/{gym_id}"
        headers = {
            "Authorization": f"Bearer {token}"
        }
        response = requests.delete(url, headers=headers)
        return response

    def list_gyms(self, token: str, params: dict = None):
        """
        Retrieve all gyms with optional filters and pagination.
        """
        url = f"{self.base_url}/api/v1/management/gyms"
        headers = {
            "Authorization": f"Bearer {token}"
        }
        response = requests.get(url, headers=headers, params=params)
        return response

    def invite_user_to_gym(self, token: str, gym_id: str, user_id: str):
        """
        Invite a user to access a specific gym.
        """
        url = f"{self.base_url}/api/v1/management/gym/{gym_id}/invite"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        payload = {
            "user_id": user_id
        }
        response = requests.post(url, headers=headers, json=payload)
        return response

    def list_users_for_gym(self, token: str, gym_id: str):
        """
        Retrieve a list of users invited to a specific gym.
        """
        url = f"{self.base_url}/api/v1/management/gym/{gym_id}/users"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }
        response = requests.get(url, headers=headers)
        return response

    def remove_user_from_gym(self, token: str, gym_id: str, user_id: str):
        """
        Revoke a user's access to a gym.
        """
        url = f"{self.base_url}/api/v1/management/gym/{gym_id}/users/{user_id}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }
        response = requests.delete(url, headers=headers)
        return response

    def create_gym_user(self, user_data: dict):
        """
        Register a new gym user.
        :param user_data: dict matching GymUserCreate schema, e.g. {"email": "...", "password": "...", ...}
        :return: Response object from requests
        """
        url = f"{self.base_url}/api/v1/gym/auth/register"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        response = requests.post(url, json=user_data, headers=headers)
        return response

    def verify_gym_email(self, token: str):
        """
        Verify gym user email using the verification token.

        :param token: Verification token (string)
        :return: Response object from requests
        """
        url = f"{self.base_url}/api/v1/gym/auth/verify-email"
        headers = {
            "Accept": "application/json",
        }
        params = {"token": token}
        response = requests.get(url, headers=headers, params=params)
        return response

    def resend_verification_email(self, email: str):
        """
        Resend gym email verification token.

        :param email: The email of the gym user
        :return: Response object
        """
        url = f"{self.base_url}/api/v1/gym/auth/resend-verification"
        payload = {"email": email}
        headers = {"Accept": "application/json", "Content-Type": "application/json"}

        response = requests.post(url, headers=headers, json=payload)
        return response

    def request_password_reset(self, email: str):
        """
        Request password reset for a gym user.

        :param email: Email address of the user
        :return: Response object from requests
        """
        url = f"{self.base_url}/api/v1/gym/auth/forgot-password"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        payload = {"email": email}
        response = requests.post(url, headers=headers, json=payload)
        return response

    def reset_gym_password(self, token: str, password: str, cpassword: str):
        """
        Reset gym user password using a valid reset token.

        :param token: Password reset token (from email)
        :param password: New password
        :param cpassword: Confirmation password (must match)
        :return: Response object from requests
        """
        url = f"{self.base_url}/api/v1/gym/auth/password-reset"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        params = {"token": token}
        payload = {
            "password": password,
            "cpassword": cpassword
        }
        response = requests.post(url, headers=headers, params=params, json=payload)
        return response

    def login_gym_user(self, email: str, password: str) -> requests.Response:
        """
        Logs in a gym user and returns the response.

        Args:
            email (str): User email.
            password (str): User password.

        Returns:
            requests.Response: The HTTP response from the login endpoint.
        """
        url = f"{self.base_url}/api/v1/gym/auth/login"
        payload = {
            "email": email,
            "password": password
        }
        headers = {
            "Content-Type": "application/json"
        }
        response = requests.post(url, json=payload, headers=headers)
        return response

    def refresh_gym_token(self, refresh_token: str) -> requests.Response:

        url = f"{self.base_url}/api/v1/gym/auth/refresh"
        payload = {"refresh_token": refresh_token}
        headers = {"Content-Type": "application/json"}
        return requests.post(url, json=payload, headers=headers)

    def gym_logout(self, token: str) -> requests.Response:
        """
        Logs out the gym user.

        Args:
            token (str): Bearer JWT access token.

        Returns:
            requests.Response: HTTP response object.
        """
        url = f"{self.base_url}/api/v1/gym/auth/logout"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        return requests.get(url, headers=headers)

    def get_gym_user_profile(self, token: str) -> requests.Response:
        """
        Retrieves the currently authenticated gym user's profile.

        Args:
            token (str): Bearer JWT access token.

        Returns:
            requests.Response: HTTP response object.
        """
        log.info(f"token:{token}")
        url = f"{self.base_url}/api/v1/gym/user/me"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        response = requests.get(url, headers=headers)
        log.info(f"response:{response}")
        return response

    def get_gym_user_by_id(self, token: str, user_id: str) -> requests.Response:
        """
        Retrieves a gym user by their unique ID.

        Args:
            token (str): Bearer access token.
            user_id (str): Unique ID of the gym user.

        Returns:
            requests.Response: Response object.
        """
        url = f"{self.base_url}/api/v1/gym/user/{user_id}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        return requests.get(url, headers=headers)

    def update_gym_user_by_id(self, access_token, user_id, payload):

        url = f"{self.base_url}/api/v1/gym/user/{user_id}"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }

        response = requests.put(url, headers=headers, json=payload)
        return response

    def delete_gym_user(self, user_id: str, token: str):

        url = f"{self.base_url}/api/v1/gym/user/{user_id}"
        headers = {
            "Authorization": f"Bearer {token}"
        }
        response = requests.delete(url, headers=headers)
        return response

    def list_gym_users(self, token, query_params=None):

        url = f"{self.base_url}/api/v1/gym/users"
        headers = {
            "Authorization": f"Bearer {token}"
        }
        response = requests.get(url, headers=headers, params=query_params or {})
        return response

    def assign_gym_user_role(self, token: str, user_id: str, role_id: str):
        """
        Assigns a role to a gym user via POST /api/v1/gym/user-role.

        Args:
            token: Valid Bearer token for authentication
            user_id: UUID of the user
            role_id: UUID of the role

        Returns:
            Response object from the API
        """
        url = f"{self.base_url}/api/v1/gym/user-role"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        payload = {"user_id": user_id, "role_id": role_id}
        # Using 'json=' ensures proper application/json encoding :contentReference[oaicite:1]{index=1}
        response = requests.post(url, headers=headers, json=payload)
        return response

    def get_gym_user_role(self, token: str, user_id: str, role_id: str):
        """
        GET /api/v1/gym/user-role/{user_id}/{role_id}
        Returns the role assignment for a gym user.
        """
        url = f"{self.base_url}/api/v1/gym/user-role/{user_id}/{role_id}"
        headers = {"Authorization": f"Bearer {token}"}
        return requests.get(url, headers=headers)

    def update_gym_user_role(self, token, user_id, role_id, update_data):
        """
        Update an existing gym user-role assignment.

        Args:

            token (str): Bearer token for authorization
            user_id (str): UUID of the user
            role_id (str): UUID of the role
            update_data (dict): Data payload for update (may contain user_id, role_id or null)

        Returns:
            Response object from requests.put()
        """
        url = f"{self.base_url}/api/v1/gym/user-role/{user_id}/{role_id}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        response = requests.put(url, json=update_data, headers=headers)
        return response

    def delete_gym_user_role(self, token: str, user_id: str, role_id: str):
        """
        DELETE /api/v1/gym/user-role/{user_id}/{role_id}
        Deletes a user-role assignment.
        """
        url = f"{self.base_url}/api/v1/gym/user-role/{user_id}/{role_id}"
        headers = {"Authorization": f"Bearer {token}"}
        return requests.delete(url, headers=headers)

    def list_gym_user_roles(self, token: str, params: dict = None):
        """
        GET /api/v1/gym/user-roles
        Returns paginated list of user-role assignments.
        """
        url = f"{self.base_url}/api/v1/gym/user-roles"
        headers = {"Authorization": f"Bearer {token}"}
        return requests.get(url, headers=headers, params=params)
