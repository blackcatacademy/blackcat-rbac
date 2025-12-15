<?php
declare(strict_types=1);

namespace BlackCat\Rbac;

use BlackCat\Core\Database;
use BlackCat\Database\Packages\RbacRoles\Criteria as RolesCriteria;
use BlackCat\Database\Packages\RbacRoles\Repository\RbacRoleRepository;
use BlackCat\Database\Packages\RbacUserRoles\Criteria as UserRolesCriteria;
use BlackCat\Database\Packages\RbacUserRoles\Repository\RbacUserRoleRepository;

final class RbacService
{
    private readonly RbacRoleRepository $roles;
    private readonly RbacUserRoleRepository $userRoles;

    public function __construct(
        private readonly Database $db,
        ?RbacRoleRepository $roles = null,
        ?RbacUserRoleRepository $userRoles = null,
    ) {
        $this->roles = $roles ?? new RbacRoleRepository($db);
        $this->userRoles = $userRoles ?? new RbacUserRoleRepository($db);
    }

    public function ensureRole(
        string $slug,
        ?string $name = null,
        ?string $description = null,
        ?int $repoId = null,
    ): int {
        $slug = self::normalizeSlug($slug);
        if ($slug === '') {
            throw new \InvalidArgumentException('role slug must not be empty');
        }

        $repoId = $repoId !== null && $repoId > 0 ? $repoId : null;
        $row = $this->roles->getByUnique(['repo_id' => $repoId, 'slug' => $slug], false);
        if (is_array($row) && isset($row['id'])) {
            $id = (int)$row['id'];
            if ($id > 0) {
                return $id;
            }
        }

        $this->roles->insert([
            'repo_id' => $repoId,
            'slug' => $slug,
            'name' => trim((string)($name ?? $slug)) ?: $slug,
            'description' => $description !== null && trim($description) !== '' ? trim($description) : null,
            'status' => 'active',
            'version' => 1,
        ]);

        return $this->lastInsertIdAsInt();
    }

    public function assignRole(
        int $userId,
        int|string $roleIdOrSlug,
        ?int $tenantId = null,
        ?string $scope = null,
        ?int $grantedBy = null,
        ?\DateTimeInterface $expiresAt = null,
        bool $autoCreateRole = true,
    ): bool {
        if ($userId <= 0) {
            throw new \InvalidArgumentException('userId must be > 0');
        }

        $roleId = $this->resolveRoleId($roleIdOrSlug, $autoCreateRole);
        $tenantId = $tenantId !== null && $tenantId > 0 ? $tenantId : null;
        $scope = self::normalizeScope($scope);
        $expiresAtSql = $expiresAt ? self::formatSqlDateTime($expiresAt) : null;

        $existingId = $this->findUserRoleId($userId, $roleId, $tenantId, $scope);
        $row = [
            'status' => 'active',
            'granted_by' => $grantedBy !== null && $grantedBy > 0 ? $grantedBy : null,
            'expires_at' => $expiresAtSql,
        ];

        if ($existingId !== null) {
            $this->userRoles->updateById($existingId, $row);
            return true;
        }

        $this->userRoles->insert([
            'user_id' => $userId,
            'role_id' => $roleId,
            'tenant_id' => $tenantId,
            'scope' => $scope,
            'status' => 'active',
            'granted_by' => $grantedBy !== null && $grantedBy > 0 ? $grantedBy : null,
            'expires_at' => $expiresAtSql,
        ]);
        return true;
    }

    public function revokeRole(
        int $userId,
        int|string $roleIdOrSlug,
        ?int $tenantId = null,
        ?string $scope = null,
    ): bool {
        if ($userId <= 0) {
            throw new \InvalidArgumentException('userId must be > 0');
        }

        $roleId = $this->resolveRoleId($roleIdOrSlug, false);
        $tenantId = $tenantId !== null && $tenantId > 0 ? $tenantId : null;
        $scope = self::normalizeScope($scope);

        $existingId = $this->findUserRoleId($userId, $roleId, $tenantId, $scope);
        if ($existingId === null) {
            return false;
        }
        $this->userRoles->updateById($existingId, [
            'status' => 'revoked',
            'expires_at' => (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s.u'),
        ]);
        return true;
    }

    public function userHasRole(
        int $userId,
        int|string $roleIdOrSlug,
        ?int $tenantId = null,
        ?string $scope = null,
    ): bool {
        if ($userId <= 0) {
            return false;
        }

        $roleId = $this->resolveRoleId($roleIdOrSlug, false);
        $tenantId = $tenantId !== null && $tenantId > 0 ? $tenantId : null;
        $scope = self::normalizeScope($scope);

        $crit = UserRolesCriteria::fromDb($this->db)
            ->where('user_id', '=', $userId)
            ->where('role_id', '=', $roleId)
            ->where('status', '=', 'active')
            ->orderBy('id', 'DESC')
            ->setPerPage(50)
            ->setPage(1);

        if ($tenantId === null) {
            $crit->isNull('tenant_id');
        } else {
            $crit->where('tenant_id', '=', $tenantId);
        }
        if ($scope === null) {
            $crit->isNull('scope');
        } else {
            $crit->where('scope', '=', $scope);
        }

        $page = $this->userRoles->paginate($crit);
        $items = is_array($page['items'] ?? null) ? (array)$page['items'] : [];
        if ($items === []) {
            return false;
        }

        $now = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        foreach ($items as $row) {
            if (!is_array($row)) {
                continue;
            }
            $expires = $row['expires_at'] ?? null;
            if ($expires === null || $expires === '') {
                return true;
            }
            if ($expires instanceof \DateTimeInterface) {
                if ($expires > $now) {
                    return true;
                }
                continue;
            }
            if (!is_string($expires)) {
                continue;
            }
            try {
                $dt = new \DateTimeImmutable($expires, new \DateTimeZone('UTC'));
                if ($dt > $now) {
                    return true;
                }
            } catch (\Throwable) {
                // ignore malformed value
            }
        }
        return false;
    }

    /**
     * Return role rows assigned to the user (active + not expired).
     *
     * @return array<int,array<string,mixed>>
     */
    public function rolesForUser(
        int $userId,
        ?int $tenantId = null,
        ?string $scope = null,
    ): array {
        if ($userId <= 0) {
            return [];
        }

        $tenantId = $tenantId !== null && $tenantId > 0 ? $tenantId : null;
        $scope = self::normalizeScope($scope);

        $crit = UserRolesCriteria::fromDb($this->db)
            ->where('user_id', '=', $userId)
            ->where('status', '=', 'active')
            ->orderBy('id', 'DESC')
            ->setPerPage(500)
            ->setPage(1);

        if ($tenantId === null) {
            $crit->isNull('tenant_id');
        } else {
            $crit->where('tenant_id', '=', $tenantId);
        }
        if ($scope === null) {
            $crit->isNull('scope');
        } else {
            $crit->where('scope', '=', $scope);
        }

        $page = $this->userRoles->paginate($crit);
        $items = is_array($page['items'] ?? null) ? (array)$page['items'] : [];
        if ($items === []) {
            return [];
        }

        $now = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        $roleIds = [];
        foreach ($items as $row) {
            if (!is_array($row)) {
                continue;
            }
            $expires = $row['expires_at'] ?? null;
            if ($expires !== null && $expires !== '') {
                try {
                    $dt = $expires instanceof \DateTimeInterface ? $expires : new \DateTimeImmutable((string)$expires, new \DateTimeZone('UTC'));
                    if ($dt <= $now) {
                        continue;
                    }
                } catch (\Throwable) {
                    continue;
                }
            }
            $rid = (int)($row['role_id'] ?? 0);
            if ($rid > 0) {
                $roleIds[$rid] = true;
            }
        }

        if ($roleIds === []) {
            return [];
        }

        $critRoles = RolesCriteria::fromDb($this->db)
            ->byIds(array_keys($roleIds))
            ->orderBy('id', 'ASC')
            ->setPerPage(min(500, count($roleIds)))
            ->setPage(1);

        $rolesPage = $this->roles->paginate($critRoles);
        $roleRows = is_array($rolesPage['items'] ?? null) ? (array)$rolesPage['items'] : [];
        return array_values(array_filter($roleRows, 'is_array'));
    }

    private function resolveRoleId(int|string $roleIdOrSlug, bool $autoCreate): int
    {
        if (is_int($roleIdOrSlug) && $roleIdOrSlug > 0) {
            return $roleIdOrSlug;
        }

        $slug = self::normalizeSlug((string)$roleIdOrSlug);
        if ($slug === '') {
            throw new \InvalidArgumentException('role id/slug must not be empty');
        }

        $row = $this->roles->getByUnique(['repo_id' => null, 'slug' => $slug], false);
        if (is_array($row) && isset($row['id'])) {
            $id = (int)$row['id'];
            if ($id > 0) {
                return $id;
            }
        }

        if (!$autoCreate) {
            throw new \RuntimeException('role_not_found');
        }

        return $this->ensureRole($slug, $slug);
    }

    private function findUserRoleId(int $userId, int $roleId, ?int $tenantId, ?string $scope): ?int
    {
        $crit = UserRolesCriteria::fromDb($this->db)
            ->where('user_id', '=', $userId)
            ->where('role_id', '=', $roleId)
            ->orderBy('id', 'DESC')
            ->setPerPage(1)
            ->setPage(1);

        if ($tenantId === null) {
            $crit->isNull('tenant_id');
        } else {
            $crit->where('tenant_id', '=', $tenantId);
        }
        if ($scope === null) {
            $crit->isNull('scope');
        } else {
            $crit->where('scope', '=', $scope);
        }

        $page = $this->userRoles->paginate($crit);
        $items = is_array($page['items'] ?? null) ? (array)$page['items'] : [];
        $row = $items[0] ?? null;
        if (!is_array($row) || !isset($row['id'])) {
            return null;
        }
        $id = (int)$row['id'];
        return $id > 0 ? $id : null;
    }

    private function lastInsertIdAsInt(): int
    {
        $id = $this->db->lastInsertId();
        if (is_string($id) && ctype_digit($id) && (int)$id > 0) {
            return (int)$id;
        }
        return 0;
    }

    private static function normalizeSlug(string $slug): string
    {
        $slug = trim($slug);
        if ($slug === '') {
            return '';
        }
        $slug = strtolower($slug);
        $slug = preg_replace('~\\s+~', '_', $slug) ?? $slug;
        return substr($slug, 0, 120);
    }

    private static function normalizeScope(?string $scope): ?string
    {
        if (!is_string($scope)) {
            return null;
        }
        $scope = trim($scope);
        if ($scope === '') {
            return null;
        }
        return substr($scope, 0, 120);
    }

    private static function formatSqlDateTime(\DateTimeInterface $dt): string
    {
        $utc = new \DateTimeZone('UTC');
        if ($dt instanceof \DateTimeImmutable) {
            return $dt->setTimezone($utc)->format('Y-m-d H:i:s.u');
        }
        return (new \DateTimeImmutable($dt->format('c')))->setTimezone($utc)->format('Y-m-d H:i:s.u');
    }
}
