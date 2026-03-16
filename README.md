IPBAuthLogin
============

This version of the extension is only tested for use in the AutoIt website.

IPBAuthLogin is a plugin for MediaWiki 1.43+ and up which integrates MediaWiki with an [Invision Power Board and Invision Community](https://invisioncommunity.com) forum's user database. By enabling the extension, it is possible to log into the MediaWiki installation using IPB user accounts. The extension creates local user accounts on MediaWiki, which are always authenticated though this extension.

As IPB usernames are not case sensitive, extension converts any username into a canonical form, to avoid duplicate local accounts being created for the same user.

Requirements
------------

* MediaWiki 1.43+
* IPS Community 4.7.23
* MySQL database for IPB
* PHP 8.0+ (Untested for older versions)
* MySQLi PHP extension

Documentation
-------------

Extensive documentation for the extension can be found on its [mediawiki.org page](https://www.mediawiki.org/wiki/Extension:IPBAuthLogin).

Troubleshooting
---------------

For debugging authentication issues, enable a dedicated MediaWiki log group in `LocalSettings.php`:

```php
$wgDebugLogGroups['IPBLoginAuth'] = '/path/to/ipbloginauth.log';
```

Then test a login and inspect the emitted records for database connectivity, query preparation errors, and password-verification outcomes.

License
-------

This extension is licensed under the included GPLv3 license.

Contributing
------------

Contributions can be made to the plugin by submitting pull requests through its [GitHub repository](https://github.com/FHannes/IPBAuthLogin).

TODO
----

* Support for account recovery through MediaWiki.
* Possible support for account creation through MediaWiki.
