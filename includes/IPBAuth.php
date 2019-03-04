<?php
/*
    IPBLoginAuth is a MediaWiki extension which authenticates users through an IPB forums database.
    Copyright (C) 2016  Frédéric Hannes

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

namespace IPBLoginAuth;

use ConfigFactory;
use User;

class IPBAuth
{

    private static $config;

    /**
     * Returns a config singleton object allowing access to the extension's configuration.
     *
     * @return \Config
     */
    public static function getConfig()
    {
        if (self::$config === null) {
            self::$config = ConfigFactory::getDefaultInstance()->makeConfig('ipbloginauth');
        }
        return self::$config;
    }

    /**
     * Creates and returns a new mysqli object to access the IPB forum database.
     *
     * @return \mysqli
     */
    public static function getSQL()
    {
        $cfg = IPBAuth::getConfig();
        return @new \mysqli(
            $cfg->get('IPBDBHost'),
            $cfg->get('IPBDBUsername'),
            $cfg->get('IPBDBPassword'),
            $cfg->get('IPBDBDatabase')
        );
    }

    /**
     * Clean up a value (username or password) before using it to query the forum database. A similar function is used
     * in the IPB software to access the database.
     *
     * @param $value
     * @return string
     */
    public static function cleanValue($value)
    {
        if ($value == "") {
            return "";
        }

        $value = preg_replace('/\\\(?!&amp;#|\?#)/', "&#092;", $value);
        $value = htmlspecialchars($value, ENT_QUOTES | ENT_HTML5);
        $value = str_replace("&#032;", " ", $value);
        $value = str_replace(array("\r\n", "\n\r", "\r"), "\n", $value);
        $value = str_replace("<!--", "&#60;&#33;--", $value);
        $value = str_replace("-->", "--&#62;", $value);
        $value = str_ireplace("<script", "&#60;script", $value);
        $value = str_replace("\n", "<br />", $value);
        $value = str_replace("$", "&#036;", $value);
        $value = str_replace("!", "&#33;", $value);
        // UNICODE
        $value = preg_replace("/&amp;#([0-9]+);/s", "&#\\1;", $value);
        $value = preg_replace('/&#(\d+?)([^\d;])/i', "&#\\1;\\2", $value);

        return $value;
    }

    /**
     * Normalizes a username based on the usernames stored in teh forum database.
     *
     * @param $username
     * @return string
     */
    public static function normalizeUsername($username)
    {
        $originalname = $username;
        $cfg = IPBAuth::getConfig();
        $sql = IPBAuth::getSQL();
        try {
            $username = IPBAuth::cleanValue($username);
            $username = $sql->real_escape_string($username);
            $prefix = $cfg->get('IPBDBPrefix');
            $ipbver = $cfg->get('IPBVersion');
            if ($ipbver >= 4) {
                $prefix .= 'core_';
            }

            // Check underscores
            $us_username = str_replace(" ", "_", $username);
            $stmt = $sql->prepare("SELECT email FROM {$prefix}members WHERE lower(name) = lower(?)");
            if ($stmt) {
                try {
                    $stmt->bind_param('s', $us_username);
                    $stmt->execute();
                    $stmt->store_result();
                    if ($stmt->num_rows == 1) {
                        $username = $us_username;
                    }
                } finally {
                    $stmt->close();
                }
            }

            // Update user
            $stmt = $sql->prepare("SELECT name FROM {$prefix}members WHERE lower(name) = lower(?)");
            if ($stmt) {
                try {
                    $stmt->bind_param('s', $username);
                    $stmt->execute();
                    $stmt->store_result();
                    if ($stmt->num_rows == 1) {
                        $stmt->bind_result($name);
                        if ($stmt->fetch()) {
                            $username = User::getCanonicalName($name, 'creatable');
                            if ($username) {
                                return $username;
                            }
                        }
                    }
                } finally {
                    $stmt->close();
                }
            }
        } finally {
            $sql->close();
        }
        return $originalname;
    }

    /**
     * Updates a \User object with data from the IPB forum database.
     *
     * @param $user
     */
    public static function updateUser(&$user)
    {
        $cfg = IPBAuth::getConfig();
        $sql = IPBAuth::getSQL();
        try {
            $username = IPBAuth::cleanValue($user->getName());
            $username = $sql->real_escape_string($username);
            $prefix = $cfg->get('IPBDBPrefix');
            $ipbver = $cfg->get('IPBVersion');
            if ($ipbver >= 4) {
                $prefix .= 'core_';
                $name_field = 'name';
            } else {
                $name_field = 'members_display_name';
            }

            // Check underscores
            $us_username = str_replace(" ", "_", $username);
            $stmt = $sql->prepare("SELECT email FROM {$prefix}members WHERE lower(name) = lower(?)");
            if ($stmt) {
                try {
                    $stmt->bind_param('s', $us_username);
                    $stmt->execute();
                    $stmt->store_result();
                    if ($stmt->num_rows == 1) {
                        $username = $us_username;
                    }
                } finally {
                    $stmt->close();
                }
            }

            // Update user
            $stmt = $sql->prepare("SELECT member_group_id, mgroup_others, email, {$name_field} FROM {$prefix}members WHERE lower(name) = lower(?)");
            if ($stmt) {
                try {
                    $stmt->bind_param('s', $username);
                    $stmt->execute();
                    $stmt->store_result();
                    if ($stmt->num_rows == 1) {
                        $stmt->bind_result($member_group_id, $mgroup_others, $email, $members_display_name);
                        if ($stmt->fetch()) {
                            $user->setEmail($email);
                            if ($member_group_id != $cfg->get('IPBGroupValidating')) {
                                $user->confirmEmail();
                            }
                            $user->setRealName($members_display_name);
                            $groups = explode(",", $mgroup_others);
                            $groups[] = $member_group_id;
                            $groupmap = $cfg->get('IPBGroupMap');
                            if (is_array($groupmap)) {
                                foreach ($groupmap as $ug_wiki => $ug_ipb) {
                                    $user_has_ug = in_array($ug_wiki, $user->getEffectiveGroups());
                                    if (in_array($ug_ipb, $groups) && !$user_has_ug) {
                                        $user->addGroup($ug_wiki);
                                    } elseif (!in_array($ug_ipb, $groups) && $user_has_ug) {
                                        $user->removeGroup($ug_wiki);
                                    }
                                }
                            }
                            $user->saveSettings();
                        }
                    }
                } finally {
                    $stmt->close();
                }
            }
        } finally {
            $sql->close();
        }
    }

    /**
     * Verifies whether a username is already in use in the IPB forum database.
     *
     * @param $username
     * @return bool
     */
    public static function userExists($username)
    {
        $sql = IPBAuth::getSQL();
        try {
            if ($sql->connect_errno) {
                return false;
            }

            $username = IPBAuth::cleanValue($username);
            $username = $sql->real_escape_string($username);
            $prefix = $cfg->get('IPBDBPrefix');
            $ipbver = $cfg->get('IPBVersion');
            if ($ipbver >= 4) {
                $prefix .= 'core_';
            }

            // Check underscores
            $us_username = str_replace(" ", "_", $username);
            $stmt = $sql->prepare("SELECT email FROM {$prefix}members WHERE lower(name) = lower(?) OR lower(name) = lower(?)");
            if ($stmt) {
                try {
                    $stmt->bind_param('ss', $username, $us_username);
                    $stmt->execute();
                    $stmt->store_result();
                    return $stmt->num_rows == 1;
                } finally {
                    $stmt->close();
                }
            } else {
                return false;
            }
        } finally {
            $sql->close();
        }
    }

    /**
     * Verifies if a supplied password matches the password hash in the IPB database.
     *
     * @param $password
     * @param $hash
     * @param $salt
     * @return bool
     */
    public static function checkIPBPassword($password, $hash, $salt)
    {
        /* IPB uses a different method in 3.x, 4.0 and 4.4 */
        if ($salt == NULL) {
            /* IPB 4.4+ */
            return password_verify($password, $hash);
            
        } elseif  ( mb_strlen( $salt ) === 22 )	{
            /* IPB 4.0 */
            $generatedHash = crypt( $password, '$2a$13$' . $salt );
            return ($generatedHash == $hash);

        } else {
            /* 3.x */
            $password = IPBAuth::cleanValue($password);
            $generatedHash = md5(md5($salt) . md5($password));
            return ($generatedHash == $hash);

		}
    }

}
