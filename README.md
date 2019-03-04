IPBAuthLogin
============

IPBAuthLogin is a plugin for MediaWiki 1.27 and up which integrates MediaWiki with an [Invision Power Board and Invision Community](https://invisioncommunity.com) forum's user database. By enabling the extension, it is possible to log into the MediaWiki installation using IPB user accounts. The extension creates local user accounts on MediaWiki, which are always authenticated though this extension.

As IPB usernames are not case sensitive, extension converts any username into a canonical form, to avoid duplicate local accounts being created for the same user.

Requirements
------------

* MediaWiki 1.27+
* Invision Power Board 3 / IPS Community 4
* MySQL database for IPB
* PHP 7.0+ (Untested for PHP 5.6 and older)
* MySQLi PHP extension

Documentation
-------------

Extensive documentation for the extension can be found on its [mediawiki.org page](https://www.mediawiki.org/wiki/Extension:IPBAuthLogin).

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