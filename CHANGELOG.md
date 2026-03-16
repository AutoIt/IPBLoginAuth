# Changelog

## 1.1.0
* Compatibility: register `UserLoggedIn` via `extension.json` hook wiring (MediaWiki 1.43 compatible).
* Bugfix: fixed `userExists()` fatal error caused by undefined config variable.
* Reliability: improved password verification fallback order for modern and legacy IPS hashes.
* Diagnostics: added structured logging for database connection, query preparation, and authentication failures.
* Bugfix: use `IDBAccessObject::READ_NORMAL` in `testUserExists()` for MediaWiki 1.43 compatibility.
* Bugfix: replaced removed `ConfigFactory::getDefaultInstance()` usage with `MediaWikiServices::getInstance()->getConfigFactory()->makeConfig(...)` for MediaWiki 1.43 compatibility.
* Bugfix: replaced removed `User::getCanonicalName()` calls with `UserNameUtils->getCanonical(...)` for MediaWiki 1.43 compatibility.
* Logging: include username directly in authentication and profile-sync log messages for easier troubleshooting with plain-text log formatters.

## 1.0.1
* Bugfix: Users could not edit their signature

## 1.0.0

* Initial release
