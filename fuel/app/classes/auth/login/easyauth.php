<?php
/**
 * EasyAuth
 *
 * @author       Yasuhiro Hayashida https://github.com/hayashida
 * @copyright    2012 Yasuhiro Hayashida
 * @license      MIT License
 */

namespace Auth;

class EasyUserUpdateException extends \FuelException {}

class Auth_Login_EasyAuth extends \Auth_Login_Driver
{
    /**
     * @var Database_Result when login successded
     */
    protected $user = null;
    
    public static function _init()
    {
        \Config::load('easyauth', true, true, true);
        
    }
    
    /**
     * Check for login
     * 
     * @return bool
     */
    protected function perform_check()
    {
        $user_id = \Session::get('user_id');
        $login_hash = \Session::get('login_hash');
        
        // only worth checking if there's both a user_id and login_hash
        if (!empty($user_id) and !empty($login_hash)) {
            $this->user = \DB::select_array(\Config::get('easyauth.field_columns', array('*')))
                            ->where(\Config::get('easyauth.field_id'), '=', $user_id)
                            ->from(\Config::get('easyauth.table_name'))
                            ->execute(\Config::get('easyauth.db_connection'))
                            ->current();
        }
        
        if ($this->user and $this->user[\Config::get('easyauth.field_login_hash')] === $login_hash) {
            return true;
        }
        
        // no valid login where still here, ensure empty session
        $this->user = false;
        \Session::destroy();
        
        return false;
    }
    
    /**
     * Check the user exists before loggin in
     * 
     * @param string $login_id
     * @param string $password
     * @return bool
     */
    public function validate_user($login_id = '', $password = '')
    {
        $login_id = trim($login_id) ? : trim(\Input::post(\Config::get('easyauth.field_login_id')));
        $password = trim($password) ? : trim(\Input::post(\Config::get('easyauth.field_password')));
        
        if (empty($login_id) or empty($password)) {
            return false;
        }
        
        $password = $this->hash_password($password);
        $this->user = \DB::select_array(\Config::get('easyauth.table_columns', array('*')))
                        ->where(\Config::get('easyauth.field_login_id'), '=', $login_id)
                        ->where(\Config::get('easyauth.field_password'), '=', $password)
                        ->from(\Config::get('easyauth.table_name'))
                        ->execute(\Config::get('easyauth.db_connection'))
                        ->current();
        
        return $this->user ?: false;
    }
    
    /**
     * Login user
     * 
     * @param string $login_id
     * @param string $password
     * @return bool
     */
    public function login($login_id = '', $password = '')
    {
        if (! ($this->user = $this->validate_user($login_id, $password))) {
            $this->user = false;
            \Session::destroy();
            return false;
        }
        
        \Session::set('user_id', $this->user[\Config::get('easyauth.field_id')]);
        \Session::set('login_hash', $this->create_login_hash());
        \Session::instance()->rotate();
        
        return true;
    }
    
    /**
     * Force login user
     * 
     * @param string $user_id
     * @return bool
     */
    public function force_login($user_id = '')
    {
        if (empty($user_id)) {
            return false;
        }
        
        $this->user = \DB::select_array(\Config::get('easyauth.table_columns', array('*')))
                        ->where(\Config::get('easyauth.field_id'), '=', $user_id)
                        ->from(\Config::get('easyauth.table_name'))
                        ->execute(\Config::get('easyauth.db_connection'))
                        ->current();
        
        if ($this->user == false) {
            $this->user = false;
            \Session::destroy();
            return false;
        }
        
        \Session::set('user_id', $this->user[\Config::get('easyauth.field_id')]);
        \Session::set('login_hash', $this->create_login_hash());
        return true;
    }
    
    /**
     * Logout user
     * 
     * @return bool
     */
    public function logout()
    {
        $this->user = false;
        \Session::destroy();
        return true;
    }
    
    /**
     * Creates a temporary hash that will validate the current login
     * 
     * @throws \EasyUserUpdateException
     * @return string
     */
    public function create_login_hash()
    {
        if (empty($this->user)) {
            throw new \EasyUserUpdateException('User not lgged in, can\'t create login hash.', 10);
        }
        
        $last_login = \Date::forge()->get_timestamp();
        $login_hash = sha1(
                        \Config::get('easyauth.login_hash_salt') .
                        $this->user[\Config::get('easyauth.field_login_id')] .
                        $last_login
                    );
        
        \DB::update(\Config::get('easyauth.table_name'))
            ->set(array(
                        \Config::get('easyauth.field_last_login') => $last_login,
                        \Config::get('easyauth.field_login_hash') => $login_hash,
                    ))
            ->where(\Config::get('easyauth.field_id'), '=',  $this->user[\Config::get('easyauth.field_id')])
            ->execute(\Config::get('easyauth.db_connection'));
        
        $this->user[\Config::get('eashauth.field_login_hash')] = $login_hash;
        
        return $login_hash;
    }
    
    /**
     * Get the user's ID
     * 
     * @return array  containing this driver's ID & the user's ID
     */
    public function get_user_id()
    {
        if (empty($this->user)) {
            return false;
        }
        
        return array($this->id, (int)$this->user[\Config::get('easyauth.field_id')]);
    }
    
    /**
     * Get the user's groups
     * 
     * @return false
     */
    public function get_groups()
    {
        return false;
    }
    
    /**
     * Get the user's emailaddress
     * 
     * @return string
     */
    public function get_email() {
        return false;
    }
    
    /**
     * Get the user's screen name
     * 
     * @return string
     */
    public function get_screen_name()
    {
        if (empty($this->user)) {
            return false;
        }
        
        return $this->user[\Config::get('easyauth.field_username')];
    }
}