from dataclasses import dataclass, asdict
from typing import Optional, List


@dataclass
class ManagementUserCreate:
    """
    Schema for creating a new management user.
    """
    email: str
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    phone_number: Optional[str] = None
    date_of_birth: Optional[str] = None
    street_address: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    zip_code: Optional[str] = None
    country: Optional[str] = None

    def to_dict(self) -> dict:
        """
        Convert to dict, skipping None values (optional fields).
        """
        return {k: v for k, v in asdict(self).items() if v is not None}

@dataclass
class AuditLogResponse:
    log_id: str
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status_code: Optional[int] = None
    route_type: Optional[str] = None
    ip_address: Optional[str] = None
    correlation_id: Optional[str] = None
    timestamp: Optional[str] = None
    # Add any other fields present in your audit log entries

@dataclass
class PaginatedAPIResponseAuditLog:
    status: int
    message: str
    data: List[AuditLogResponse]
    total: int
    page: int
    page_size: int
    total_pages: int