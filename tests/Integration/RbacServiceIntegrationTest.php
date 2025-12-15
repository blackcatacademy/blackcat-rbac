<?php
declare(strict_types=1);

namespace BlackCat\Rbac\Tests\Integration;

use BlackCat\Core\Database;
use BlackCat\Database\Packages\CryptoAlgorithms\CryptoAlgorithmsModule;
use BlackCat\Database\Packages\KmsProviders\KmsProvidersModule;
use BlackCat\Database\Packages\KmsKeys\KmsKeysModule;
use BlackCat\Database\Packages\RbacRepositories\RbacRepositoriesModule;
use BlackCat\Database\Packages\RbacRoles\RbacRolesModule;
use BlackCat\Database\Packages\RbacUserRoles\RbacUserRolesModule;
use BlackCat\Database\Packages\SigningKeys\SigningKeysModule;
use BlackCat\Database\Packages\Tenants\TenantsModule;
use BlackCat\Database\Packages\Users\Repository\UserRepository;
use BlackCat\Database\Packages\Users\UsersModule;
use BlackCat\Rbac\RbacService;
use PHPUnit\Framework\TestCase;

/**
 * Requires a real DB (MySQL/Postgres); skipped unless DB_DSN is provided.
 *
 * @runInSeparateProcess
 * @preserveGlobalState disabled
 */
final class RbacServiceIntegrationTest extends TestCase
{
    public function testAssignAndCheckRole(): void
    {
        $db = $this->initDbOrSkip();
        $dialect = $db->dialect();

        // Postgres views use digest(...) => requires pgcrypto extension.
        if (method_exists($dialect, 'isPg') && $dialect->isPg()) {
            $db->exec('CREATE EXTENSION IF NOT EXISTS pgcrypto;');
        }

        (new UsersModule())->install($db, $dialect);
        (new TenantsModule())->install($db, $dialect);
        (new KmsProvidersModule())->install($db, $dialect);
        (new KmsKeysModule())->install($db, $dialect);
        (new CryptoAlgorithmsModule())->install($db, $dialect);
        (new SigningKeysModule())->install($db, $dialect);
        (new RbacRepositoriesModule())->install($db, $dialect);
        (new RbacRolesModule())->install($db, $dialect);
        (new RbacUserRolesModule())->install($db, $dialect);

        $this->wipeTables($db, [
            'rbac_user_roles',
            'rbac_roles',
            'rbac_repositories',
            'signing_keys',
            'crypto_algorithms',
            'kms_keys',
            'kms_providers',
            'tenants',
            'users',
        ]);

        $userId = $this->createUser($db);

        $svc = new RbacService($db);
        self::assertTrue($svc->assignRole($userId, 'admin'));
        self::assertTrue($svc->userHasRole($userId, 'admin'));
        self::assertFalse($svc->userHasRole($userId, 'nonexistent-role'));
    }

    private function initDbOrSkip(): Database
    {
        $dsn = (string)(getenv('DB_DSN') ?: '');
        if ($dsn === '') {
            self::markTestSkipped('Set DB_DSN to run integration tests.');
        }

        Database::init([
            'dsn' => $dsn,
            'user' => getenv('DB_USER') ?: null,
            'pass' => getenv('DB_PASSWORD') ?: null,
        ]);

        return Database::getInstance();
    }

    private function createUser(Database $db): int
    {
        $repo = new UserRepository($db);
        $repo->insert([
            'password_hash' => 'x',
            'password_algo' => 'plaintext-test-only',
        ]);

        $id = $db->lastInsertId();
        if (is_string($id) && ctype_digit($id) && (int)$id > 0) {
            return (int)$id;
        }

        $row = $db->fetch('SELECT id FROM users ORDER BY id DESC LIMIT 1') ?: [];
        $val = $row['id'] ?? null;
        $userId = is_numeric($val) ? (int)$val : 0;
        if ($userId <= 0) {
            throw new \RuntimeException('Unable to determine inserted user id');
        }
        return $userId;
    }

    /**
     * @param list<string> $tables
     */
    private function wipeTables(Database $db, array $tables): void
    {
        foreach ($tables as $table) {
            $table = trim($table);
            if ($table === '') {
                continue;
            }
            try {
                $db->exec('DELETE FROM ' . $table);
            } catch (\Throwable) {
            }
        }
    }
}

