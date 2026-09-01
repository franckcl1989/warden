"""Built-in roles and the permission matrix (docs/DATA_MODEL.md §3.2).

operationId: roles_list. Read-only view of the frozen SECURITY.md §3.1
matrix; there is no roles table and no custom roles. Any authenticated user
may read it (the matrix is public design; login itself stays the only
anonymous endpoint).
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.deps import AuthContext, get_auth_context
from app.domain.roles import PERMISSION_MATRIX, Role

router = APIRouter(prefix="/roles", tags=["roles"])


class RoleView(BaseModel):
    role: str
    permissions: list[str]


class RolesListResponse(BaseModel):
    roles: list[RoleView]


@router.get(
    "",
    operation_id="roles_list",
    response_model=RolesListResponse,
    responses={"401": {"description": "unauthenticated/session_expired"}},
)
def roles_list(_context: Annotated[AuthContext, Depends(get_auth_context)]) -> RolesListResponse:
    return RolesListResponse(
        roles=[
            RoleView(
                role=role.value,
                permissions=sorted(PERMISSION_MATRIX[role]),
            )
            for role in (Role.ADMIN, Role.OPERATOR, Role.VIEWER)
        ]
    )
