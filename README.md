# BlackCat RBAC

`blackcat-rbac` je samostatný modul pro RBAC nad `blackcat-database` (packages `rbac-*`).

- Jediný zdroj pravdy pro tabulky/views je `blackcat-database`.
- Bez raw PDO v aplikační logice: práce s DB přes generated repositories.

## Instalace

```bash
composer require blackcatacademy/blackcat-rbac
```

## Použití

```php
use BlackCat\Core\Database;
use BlackCat\Rbac\RbacService;

$rbac = new RbacService(Database::getInstance());
$rbac->assignRole(userId: 123, roleIdOrSlug: 'admin');
```

## Legacy kompatibilita (shim pro staré core API)

Pokud někde existuje staré volání `RBAC::assignRole($pdo, ...)`, tak `blackcat-core/src/RBAC.php` je nyní shim, který deleguje na `BlackCat\\Rbac\\CoreCompat\\CoreRBAC` (po instalaci tohoto modulu).

