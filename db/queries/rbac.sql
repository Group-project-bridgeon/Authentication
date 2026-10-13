-- =========================================================
-- ROLES
-- =========================================================

-- name: CreateRole :one
INSERT INTO identity_roles (
    name,
    description,
    is_system
)
VALUES (
    $1,
    $2,
    $3
)
RETURNING *;


-- name: GetRoleByID :one
SELECT *
FROM identity_roles
WHERE id = $1;


-- name: GetRoleByName :one
SELECT *
FROM identity_roles
WHERE name = $1;


-- name: ListRoles :many
SELECT *
FROM identity_roles
ORDER BY name;


-- =========================================================
-- PERMISSIONS
-- =========================================================

-- name: CreatePermission :one
INSERT INTO identity_permissions (
    resource,
    action,
    description
)
VALUES (
    $1,
    $2,
    $3
)
RETURNING *;


-- name: GetPermissionByID :one
SELECT *
FROM identity_permissions
WHERE id = $1;


-- name: GetPermissionByResourceAction :one
SELECT *
FROM identity_permissions
WHERE resource = $1
  AND action = $2;


-- name: ListPermissions :many
SELECT *
FROM identity_permissions
ORDER BY resource, action;


-- =========================================================
-- USER ROLES
-- =========================================================

-- name: AssignRoleToUser :one
INSERT INTO identity_user_roles (
    user_id,
    role_id,
    scope_type,
    scope_id,
    assigned_by
)
VALUES (
    $1,
    $2,
    $3,
    $4,
    $5
)
RETURNING *;


-- name: GetUserRole :one
SELECT *
FROM identity_user_roles
WHERE user_id = $1
  AND role_id = $2
  AND scope_type = $3
  AND scope_id IS NOT DISTINCT FROM $4;


-- name: GetUserRoles :many
SELECT *
FROM identity_user_roles
WHERE user_id = $1
ORDER BY assigned_at;


-- name: GetUserRolesByScope :many
SELECT *
FROM identity_user_roles
WHERE user_id = $1
  AND scope_type = $2
  AND scope_id IS NOT DISTINCT FROM $3
ORDER BY assigned_at;


-- name: RemoveRoleFromUser :exec
DELETE FROM identity_user_roles
WHERE user_id = $1
  AND role_id = $2
  AND scope_type = $3
  AND scope_id IS NOT DISTINCT FROM $4;


-- =========================================================
-- ROLE PERMISSIONS
-- =========================================================

-- name: AssignPermissionToRole :one
INSERT INTO identity_role_permissions (
    role_id,
    permission_id
)
VALUES (
    $1,
    $2
)
RETURNING *;


-- name: RemovePermissionFromRole :exec
DELETE FROM identity_role_permissions
WHERE role_id = $1
  AND permission_id = $2;


-- name: GetRolePermissions :many
SELECT p.*
FROM identity_permissions AS p
INNER JOIN identity_role_permissions AS rp
    ON rp.permission_id = p.id
WHERE rp.role_id = $1
ORDER BY p.resource, p.action;


-- =========================================================
-- USER AUTHORIZATION
-- =========================================================

-- name: GetUserPermissions :many
SELECT DISTINCT p.*
FROM identity_permissions AS p
INNER JOIN identity_role_permissions AS rp
    ON rp.permission_id = p.id
INNER JOIN identity_user_roles AS ur
    ON ur.role_id = rp.role_id
WHERE ur.user_id = $1;


-- name: GetUserPermissionsByScope :many
SELECT DISTINCT p.*
FROM identity_permissions AS p
INNER JOIN identity_role_permissions AS rp
    ON rp.permission_id = p.id
INNER JOIN identity_user_roles AS ur
    ON ur.role_id = rp.role_id
WHERE ur.user_id = $1
  AND (
      ur.scope_type = 'GLOBAL'
      OR (
          ur.scope_type = $2
          AND ur.scope_id = $3
      )
  );