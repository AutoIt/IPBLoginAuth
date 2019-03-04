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

namespace IPBLoginAuth\Auth;

use IPBLoginAuth\IPBAuth;

use MediaWiki\Auth\AbstractPrimaryAuthenticationProvider;
use MediaWiki\Auth\AuthenticationRequest;
use MediaWiki\Auth\AuthenticationResponse;
use MediaWiki\Auth\AuthManager;
use MediaWiki\Auth\PrimaryAuthenticationProvider;

use Hooks;
use StatusValue;
use User;

class IPBAuthenticationProvider extends AbstractPrimaryAuthenticationProvider
{

    public function __construct()
    {
        Hooks::register('UserLoggedIn', [$this, 'onUserLoggedIn']);
    }

    public function autoCreatedAccount($user, $source)
    {

    }

    public function accountCreationType()
    {
        return PrimaryAuthenticationProvider::TYPE_NONE;
    }

    public function beginPrimaryAccountCreation($user, $creator, array $reqs)
    {
        return AuthenticationResponse::ABSTAIN;
    }

    public function beginPrimaryAuthentication(array $reqs)
    {
        $req = AuthenticationRequest::getRequestByClass($reqs, IPBAuthenticationRequest::class);
        if (!$req) {
            return AuthenticationResponse::newFail(
                wfMessage('unexpected-error')
            );
        }

        $cfg = IPBAuth::getConfig();
        $sql = IPBAuth::getSQL();
        try {
            if ($sql->connect_errno) {
                return AuthenticationResponse::newFail(
                    wfMessage('db-access-error')
                );
            }

            $username = IPBAuth::cleanValue($req->username);
            $username = $sql->real_escape_string($username);
            $password = $req->password;
            $prefix = $cfg->get('IPBDBPrefix');
            $ipbver = $cfg->get('IPBVersion');
            if ($ipbver >= 4) {
                $prefix .= 'core_';
                // user group(s) 'ibf_core_groups.g_view_board' value is not checked
                $ban_check = ' AND temp_ban != -1 AND temp_ban < UNIX_TIMESTAMP()';
            } else {
                $ban_check = '';
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
            } else {
                return AuthenticationResponse::newFail(
                    wfMessage('db-error')
                );
            }

            // Check user
            $stmt = $sql->prepare("SELECT name, members_pass_hash, members_pass_salt FROM {$prefix}members WHERE (lower(name) = lower(?) OR lower(email) = lower(?)) {$ban_check}");
            if ($stmt) {
                try {
                    $stmt->bind_param('ss', $username, $username);
                    $stmt->execute();
                    $stmt->store_result();

                    $success = false;
                    if ($stmt->num_rows == 1) {
                        $stmt->bind_result($name, $members_pass_hash, $members_pass_salt);
                        if ($stmt->fetch()) {
                            $success = IPBAuth::checkIPBPassword($password, $members_pass_hash, $members_pass_salt);
                        }
                    }
                    if ($success) {
                        $username = User::getCanonicalName($name, 'creatable');
                        if (!$username) {
                            $username = $req->username;
                        }
                        return AuthenticationResponse::newPass($username);
                    } else {
                        return AuthenticationResponse::newFail(
                            wfMessage('no-user-error')
                        );
                    }
                } finally {
                    $stmt->close();
                }
            } else {
                return AuthenticationResponse::newFail(
                    wfMessage('db-error')
                );
            }
        } finally {
            $sql->close();
        }
    }

    public function getAuthenticationRequests($action, array $options)
    {
        switch ($action) {
            case AuthManager::ACTION_LOGIN:
                return [new IPBAuthenticationRequest()];
            default:
                return [];
        }
    }

    public static function onUserLoggedIn($user)
    {
        // When a user logs in, update the local account with information from the IPB database.
        IPBAuth::updateUser($user);
    }

    public function providerAllowsAuthenticationDataChange(AuthenticationRequest $req, $checkData = true)
    {
        if (get_class($req) === IPBAuthenticationRequest::class) {
            return StatusValue::newGood();
        } else {
            return StatusValue::newGood('ignored');
        }
    }

    public function providerAllowsPropertyChange($property)
    {
        // Allow users to change their signature
	    return $property == 'nickname';
    }

    public function providerChangeAuthenticationData(AuthenticationRequest $req)
    {
        // Account changes are not implemented
    }

    public function providerNormalizeUsername($username)
    {
        return IPBAuth::normalizeUsername($username);
    }

    public function testForAccountCreation($user, $creator, array $reqs)
    {
        // Account creation is not implemented
    }

    public function testUserExists($username, $flags = User::READ_NORMAL)
    {
        return IPBAuth::userExists($username);
    }

}
