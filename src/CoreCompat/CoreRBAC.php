<?php
declare(strict_types=1);

namespace BlackCat\Rbac\CoreCompat;

use BlackCat\Core\Database;
use BlackCat\Rbac\RbacService;

/**
 * Backwards-compat facade for the legacy global `RBAC` helper from blackcat-core.
 */
final class CoreRBAC
{
    private static ?RbacService $rbac = null;

    private function __construct() {}

    private static function svc(): RbacService
    {
        if (self::$rbac === null) {
            if (!Database::isInitialized()) {
                throw new \RuntimeException('Database is not initialized (expected BlackCat\\Core\\Database singleton).');
            }
            self::$rbac = new RbacService(Database::getInstance());
        }
        return self::$rbac;
    }

    public static function assignRole(\PDO $db, int $userId, mixed $roleIdOrName): bool
    {
        Database::initFromPdo($db);
        return self::svc()->assignRole($userId, is_int($roleIdOrName) ? $roleIdOrName : (string)$roleIdOrName);
    }

    public static function revokeRole(\PDO $db, int $userId, mixed $roleIdOrName): bool
    {
        Database::initFromPdo($db);
        return self::svc()->revokeRole($userId, is_int($roleIdOrName) ? $roleIdOrName : (string)$roleIdOrName);
    }

    public static function userHasRole(\PDO $db, int $userId, string $roleName): bool
    {
        Database::initFromPdo($db);
        return self::svc()->userHasRole($userId, $roleName);
    }

    public static function getRolesForUser(\PDO $db, int $userId): array
    {
        Database::initFromPdo($db);
        return self::svc()->rolesForUser($userId);
    }

    public static function createRole(\PDO $db, string $name, ?string $description = null): ?int
    {
        Database::initFromPdo($db);
        $id = self::svc()->ensureRole($name, $name, $description);
        return $id > 0 ? $id : null;
    }
}
