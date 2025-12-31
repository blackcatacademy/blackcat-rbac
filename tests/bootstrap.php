<?php
declare(strict_types=1);

$autoloadCandidates = [
    __DIR__ . '/../vendor/autoload.php',
    __DIR__ . '/../../blackcat-core/vendor/autoload.php',
    __DIR__ . '/../../blackcat-database/vendor/autoload.php',
    __DIR__ . '/../../blackcat-crypto/vendor/autoload.php',
];

$autoloadFound = false;
foreach ($autoloadCandidates as $candidate) {
    if (is_file($candidate)) {
        require $candidate;
        $autoloadFound = true;
        break;
    }
}

if (!$autoloadFound) {
    throw new RuntimeException('Cannot find an autoloader; run composer install or use the monorepo vendor.');
}

function bcrbac_register_psr4(string $prefix, string $dir): void
{
    if (!is_dir($dir)) {
        return;
    }

    spl_autoload_register(static function (string $class) use ($prefix, $dir): void {
        if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
            return;
        }

        $relative = substr($class, strlen($prefix));
        $path = $dir . '/' . str_replace('\\', '/', $relative) . '.php';
        if (is_file($path)) {
            require $path;
        }
    }, true, true);
}

bcrbac_register_psr4('BlackCat\\Rbac\\', __DIR__ . '/../src');
bcrbac_register_psr4('BlackCat\\Database\\', __DIR__ . '/../../blackcat-database/src');
bcrbac_register_psr4('BlackCat\\Database\\Packages\\Users\\', __DIR__ . '/../../blackcat-database/packages/users/src');
bcrbac_register_psr4('BlackCat\\Database\\Packages\\Tenants\\', __DIR__ . '/../../blackcat-database/packages/tenants/src');
bcrbac_register_psr4('BlackCat\\Database\\Packages\\KmsProviders\\', __DIR__ . '/../../blackcat-database/packages/kms-providers/src');
bcrbac_register_psr4('BlackCat\\Database\\Packages\\KmsKeys\\', __DIR__ . '/../../blackcat-database/packages/kms-keys/src');
bcrbac_register_psr4('BlackCat\\Database\\Packages\\CryptoAlgorithms\\', __DIR__ . '/../../blackcat-database/packages/crypto-algorithms/src');
bcrbac_register_psr4('BlackCat\\Database\\Packages\\SigningKeys\\', __DIR__ . '/../../blackcat-database/packages/signing-keys/src');
bcrbac_register_psr4('BlackCat\\Database\\Packages\\RbacRepositories\\', __DIR__ . '/../../blackcat-database/packages/rbac-repositories/src');
bcrbac_register_psr4('BlackCat\\Database\\Packages\\RbacRoles\\', __DIR__ . '/../../blackcat-database/packages/rbac-roles/src');
bcrbac_register_psr4('BlackCat\\Database\\Packages\\RbacUserRoles\\', __DIR__ . '/../../blackcat-database/packages/rbac-user-roles/src');
bcrbac_register_psr4('BlackCat\\DatabaseCrypto\\', __DIR__ . '/../../blackcat-database-crypto/src');
bcrbac_register_psr4('BlackCat\\Crypto\\', __DIR__ . '/../../blackcat-crypto/src');
bcrbac_register_psr4('BlackCat\\Core\\', __DIR__ . '/../../blackcat-core/src');
