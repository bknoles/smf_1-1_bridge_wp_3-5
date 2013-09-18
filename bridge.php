<?php
/*
Plugin Name: SMF Bridge
Plugin URI: http://code.google.com/p/wp-smf-bridge
Description: User registration and login bridge between Wordpress and Simple Machine Forum
Author: Jonathan "JonnyFunFun" Enzinna
Version: 0.3.1
Author URI: http://www.jonnyfunfun.com/
*/

class smf_bridge {
    static $bridge_active = false;
    static $smf_dir = '';
    static $reg_override = 0;
    static $smf_dbopts = array();
    static $smf_settings = array();

    /* version
     * @public
     * Returns the current software version
     */
    function version() { return 0.2; }

    /* load
     * @public
     * Performs functions needed when we load, such as checking the configuration and
     * including the necessary files for the API
     */
    function load() {
	if (get_option('smf_bridge_setup_complete') == 1) {
	    // Load the settings
	    self::$smf_dir = ABSPATH.get_option('smf_bridge_smfdir');
	    self::$reg_override = (get_option('smf_bridge_regoverride')) ? get_option('smf_bridge_regoverride') : 0;
	    if (file_exists(self::$smf_dir."Settings.php"))
		require(self::$smf_dir."Settings.php");
	    else {
		delete_option('smf_bridge_setup_complete');
		return false;
	    }
	    if (!defined('SMF_API'))
	       require(dirname(__FILE__)."/smf_1-1_api.php");
	    self::$bridge_active = true;
	    self::$smf_dbopts['user'] = $db_user;
	    self::$smf_dbopts['pass'] = $db_passwd;
	    self::$smf_dbopts['host'] = $db_server;
	    self::$smf_dbopts['prefix'] = $db_prefix;
	    self::$smf_dbopts['name'] = $db_name;
	    self::$smf_settings = $smf_settings;
	    return true;
	} else return false;
    }

    /* uservalid
     * @public [filter]
     * Checks to make sure the desired username during registration is not already
     * taken by SMF
     */
    function uservalid($valid,$username) {
	if (!self::$bridge_active) return;
	$uname = sanitize_user($username);
	if (!$valid)
	    return false;
	if ($uname != $username)
	    return false;
	if (self::getSMFId($uname))
	    return false;
	if (self::getSMFId(strtolower($uname)))
	    return false;
	return true;
    }

    /* add_menu
     * @public
     * Add the admin menu link
     */
    function add_menu() {
	add_submenu_page('options-general.php','SMF Bridge Settings','SMF Bridge',8,__FILE__,array('smf_bridge','settings'));
    }

    /* settings
     * @public
     * Draws the settings page to change the bridge configuration
     */
    function settings() {
	$prev_active = self::$bridge_active;
	echo '<div class="wrap"><h2>SMF Bridge Settings</h2></div>';
	if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	    // Save settings
	    switch ($_POST['action']) {
		case "save":
		    if (substr($_POST['smf_relpath'],-1) != '/')
			$_POST['smf_relpath'] = $_POST['smf_relpath'].'/';
		    if (!get_option('smf_bridge_smfdir'))
			add_option('smf_bridge_smfdir',$_POST['smf_relpath']);
		    else
			update_option('smf_bridge_smfdir',$_POST['smf_relpath']);
		    // Double check the bridge dir before activating
		    if (file_exists(ABSPATH.get_option('smf_bridge_smfdir')))
			add_option('smf_bridge_setup_complete',1);
		    else
			delete_option('smf_bridge_setup_complete');
		    echo '<div id="message" class="updated fade">Settings saved!</div>';
		    break;
		case "user-sync":
            $x = 0;
			//$x = self::syncusers();
		    echo '<div id="message" class="updated fade">'.$x.' Users Synchronized Successfully!</div>';
		    break;
	    }
	    self::load();
    	}
	if (!self::$bridge_active) {
	    // Let them know we're not fully set up!
	    echo '<div id="message" class="updated fade">SMF Bridge has not been configured properly and is not active!</div>';
	} elseif ((self::$bridge_active) && ($_SERVER['REQUEST_METHOD'] == "POST") && (!$prev_active)) {
	    echo '<div id="message" class="updated fade">SMF Bridge is now active!</div>';
	}
	if ((get_option('smf_bridge_smfdir')) && (!file_exists(ABSPATH.get_option('smf_bridge_smfdir').'Settings.php')))
	    echo '<div id="message" class="updated fade">Your SMF path is invalid - could not locate Settings.php in <em>'.ABSPATH.get_option('smf_bridge_smfdir').'</em></div>';
?>
    <form action="<?=$_SERVER['REQUEST_URI']?>" method="POST">
	<input type="hidden" name="action" value="save"/>
	<table width="100%" cellspacing="2" cellpadding="5" class="editform">
	<tr>
	    <th width="33%" scope="row" valign="top">Forum Path:<br />
		<font style="font-size: 8px;"><em>URI relative to Wordpress root<br />
		 i.e - "forum/" places your forums in <?=ABSPATH?>forum/</em></font>
	    </th>
	    <td>
	    <input type="text" name="smf_relpath" value="<?=(get_option('smf_bridge_smfdir')) ? get_option('smf_bridge_smfdir') : ''?>" maxlength="256" style="width: 250px;"/>
	    </td>
	</tr>
	<tr><td colspan="2" style="height: 18px;"></td></tr>
	<tr>
	    <td>&nbsp;</td>
	    <td>
		<input type="submit" value="Save Settings"/>
	    </td>
	</tr>
	</table>
    </form><br />
    <legend><em>Maintenance Options</em></legend>
    <table width="100%" cellspacing="2" cellpadding="5" class="editform">
	<tr>
	    <th width="33%" valign="top" scope="row">Manual User Sync:</th>
	    <td>
		<form action="<?=$_SERVER['REQUEST_URI']?>" method="POST">
		    <input type="hidden" name="action" value="user-sync"/>
		    <input type="submit" value="Synchronize Users"/>
		</form>
	    </td>
	<tr>
    </table>
<?	
    }

    /* login
     * @public
     * Occurs when a user logs in to WordPress, crowbars them in to SMF and syncs profiles for sanity
     */
    function login() {    
	if (!self::$bridge_active) return;
	if (!$_POST['wp-submit'] || $_POST['wp-submit'] != 'Log In') return;
	//if (!is_user_logged_in()) return;
	//$user = get_userdatabylogin($_POST['log']);
    $user = get_user_by('login', $_POST['log']);
	if ($user) {
		self::crowbar();
		self::syncprofile($user->ID,true);
	} else {
		// update wordpress password if we exist
		if (!$smf_cxn)
            global $wpdb;
                    $smf_cxn = mysql_connect(self::$smf_dbopts['host'],self::$smf_dbopts['user'],self::$smf_dbopts['pass']) or trigger_error(mysql_error(),E_USER_ERROR);
                $user_exists = $wpdb->get_row("SELECT id FROM $wpdb->users WHERE UPPER(user_login) = UPPER('". $_POST['log'] . "')");		
		if ($user_exists) {
			$SQL = "SELECT passwd, passwordSalt FROM ".self::$smf_dbopts['prefix']."members WHERE UPPER(memberName) = UPPER('".$_POST['log']."')";
			if (!$rs = mysql_query($SQL,$smf_cxn)) trigger_error(mysql_error(),E_USER_ERROR);
			if (mysql_num_rows($rs) > 0) {
				list($password,$salt) = mysql_fetch_array($rs, MYSQL_NUM);
				if (sha1($_POST['pwd'].$sald) == $password) {
					$newpass = wp_hash_password($_POST['pwd']);
					$SQL = "UPDATE ".$wpdb->prefix."users SET user_pass='$newpass' WHERE UPPER(user_login)=UPPER('".$_POST['log']."') LIMIT 1";
				}
			}
		} else {
			//self::syncusers();
			$SQL = "SELECT passwd, passwordSalt FROM ".self::$smf_dbopts['prefix']."members WHERE UPPER(memberName) = UPPER('".$_POST['log']."')";
                        if (!$rs = mysql_query($SQL,$smf_cxn)) trigger_error(mysql_error(),E_USER_ERROR);
                        if (mysql_num_rows($rs) > 0) {
                                list($password,$salt) = mysql_fetch_array($rs, MYSQL_NUM);
                                if (sha1($_POST['pwd'].$sald) == $password) {
					wp_update_user(array(
						"user_login" => $_POST['log'],
						"user_pass" => $_POST['pwd']
					));
					//$tgt_user = get_userdatabylogin($_POST['log']);
                    $tgt_user = get_user_by('login', $_POST['log']);
					if ($tgt_user) wp_set_current_user($tgt_user->ID,$tgt_user->user_login);
                                }
                        }
		}
	}
    }

    /* logout
     * @public
     * Occurs when a use logs out of WordPress, logs them out of SMF, too!
     */
    function logout() {
	if (!self::$bridge_active) return;
	smf_sessionClose();
	smf_setLoginCookie(0,$user->user_login,'',true);	
    }

    /* register
     * @public
     * Occurs when a user registers on WordPress - this registers them with SMF
     */
    function register($userID) {	    
	if (!self::$bridge_active) return;
	global $user_login,$user_email,$password;
	$user_status = ($smf_settings['registration_method'] == 2) ? 3 : 1;
	$user = get_userdata($userID);
	if (!self::getSMFId($user->user_login))
	    smf_registerMember($user->user_login, $user->user_email, $user->user_password, $user_status);
	return true;
    }

    /* syncprofile
     * @public
     * Synchronizes the user's profile information by WordPress userID
     */
    function syncprofile($userID,$regularSync=false) {	    
	if (!self::$bridge_active) return;
	global $userdata,$smf_user_info;
	get_currentuserinfo();
	$user = get_userdata($userID);
	$smfID = $smf_user_info['id'];
	// Perform only a "regular" sync - just make sure everything coincides - TODO
	if ($regularSync) {
	}
	// We obviously only want to force outbound (to SMF) sync if we're POST'ing
	if ($_SERVER['REQUEST_METHOD'] == 'POST') {
            if (!$smf_cxn)
                    $smf_cxn = mysql_connect(self::$smf_dbopts['host'],self::$smf_dbopts['user'],self::$smf_dbopts['pass']) or trigger_error(mysql_error(),E_USER_ERROR);
	    $pass = $_POST['pass1'];
		$SQL = "SELECT passwd, passwordSalt FROM ".self::$smf_dbopts['prefix']."members WHERE UPPER(memberName) = UPPER('".$user->user_login."')";
		if (!$rs = mysql_query($SQL,$smf_cxn)) trigger_error(mysql_error(),E_USER_ERROR);
		if (mysql_num_rows($rs) > 0) {
		    list($password,$salt) = mysql_fetch_array($rs, MYSQL_NUM);
		    $pass = sha1($_POST['pass1'] . $salt);
		}
	    $SQL = "UPDATE ".self::$smf_dbopts['prefix']."members SET websiteUrl='".addslashes($_POST['url'])."',
		AIM='".addslashes($_POST['aim'])."', YIM='".addslashes($_POST['yim'])."',
		passwd='".$pass."',emailAddress='".addslashes($_POST['email'])."', realName='".
		addslashes($_POST['first_name'].' '.$_POST['last_name'])."',
		signature='".addslashes($_POST['description'])."'
		WHERE UPPER(memberName)=UPPER('$user->user_login') LIMIT 1";
	    mysql_query($SQL,$smf_cxn) or trigger_error(mysql_error(),E_USER_ERROR);
	}
    }

    /* getSMFId
     * @private
     * Returns the member id from the SMF table based on username
     */
    private function getSMFId($username) {
	if (!self::$bridge_active) return;
	$smf_cxn = mysql_connect(self::$smf_dbopts['host'],self::$smf_dbopts['user'],self::$smf_dbopts['pass']);
	$SQL = "SELECT ID_MEMBER FROM ".self::$smf_dbopts['prefix']."members WHERE UPPER(memberName)=UPPER('$username') LIMIT 1";
	if (!$rs = mysql_query($SQL,$smf_cxn)) {
		trigger_error(mysql_error(),E_USER_WARNING);
		return null;
	} else {
		return mysql_fetch_array($rs, MYSQL_ASSOC)->ID_MEMBER;
	}	
    }

    /* crowbar
     * @private
     * Performs the login 'crowbar' into SMF
     */
    private function crowbar() {	    
	if (!self::$bridge_active) return;
	if (!is_user_logged_in()) return;
	$user = wp_get_current_user();
	// Fetch the password and salt so we can pass the encrypted guy to the
	// cookie setting function...
	$smf_cxn = mysql_connect(self::$smf_dbopts['host'],self::$smf_dbopts['user'],self::$smf_dbopts['pass']);
	$SQL = "SELECT passwd, passwordSalt FROM ".self::$smf_dbopts['prefix']."members WHERE memberName = '".$user->user_login."'";
	if (!$rs = mysql_query($SQL,$smf_cxn)) trigger_error(mysql_error(),E_USER_ERROR);
	if (mysql_num_rows($rs) > 0) {
	    list($password,$salt) = mysql_fetch_array($rs, MYSQL_NUM);
	    $passwd = sha1($password . $salt);
	} else {
	    // If we didn't find the user, perhaps we need to sync and try again?
		//if (self::syncusers() > 0)
		//self::crowbar();
	    return;
	}
	smf_setLoginCookie(21600,$user->user_login,passwd,true);
	smf_authenticateUser();	
    }

    /* syncusers
     * @private
     * Synchronizes all users across the two databases
     */
    private function syncusers() {
	global $wpdb;
	if (!self::$bridge_active) return;
	if (!function_exists('wp_update_user'))
	    include(ABSPATH.'/wp-includes/registration.php');
	$smf_cxn = mysql_connect(self::$smf_dbopts['host'],self::$smf_dbopts['user'],self::$smf_dbopts['pass']);
	$SQL = "SELECT UPPER(memberName) FROM ".self::$smf_dbopts['prefix']."members";
	if (!$rs = mysql_query($SQL,$smf_cxn)) {
	    // Since this is not a critical step, we'll just throw a warning instead
	    // of bombing the entire app...
	    trigger_error(mysql_error(),E_USER_ERROR);
	    return;
	}
	$smf_users = array();
	while ($row = mysql_fetch_array($rs,MYSQL_NUM))
		array_push($smf_users,$row[0]);
	$SQL = "SELECT UPPER(user_login) FROM ".$wpdb->prefix."users";
	$wp_users = $wpdb->get_col($SQL);
	if (sizeof($smf_users) == sizeof($wp_users))	
	    return 0;
	$sync_count = 0;

	foreach ($wp_users as $usr) {
	    if (!in_array($usr,$smf_users)) {
		// Sync this user to SMF!
		$user_status = ($smf_settings['registration_method'] == 2) ? 3 : 1;
        $user = get_user_by('login', $usr);
		smf_registerMember($user->user_login, $user->user_email, $user->user_password, 1);
		//self::syncprofile($user->user_id, true);
		++$sync_count;
	    }
	}
	foreach ($smf_users as $usr) {
	    if (!in_array($usr,$wp_users)) {
		// Sync this user to WP!
		$SQL = "SELECT memberName, emailAddress,realName FROM ".self::$smf_dbopts['prefix']."members WHERE UPPER(memberName)=UPPER('$usr') LIMIT 1";
		 if (!$rs = mysql_query($SQL,$smf_cxn)) {
		    // Since this is not a critical step, we'll just throw a warning instead
		    // of bombing the entire app...
		    trigger_error(mysql_error(),E_USER_ERROR);
		    return;
		}
		list($login_name,$email,$name) = mysql_fetch_array($rs);
        // Grab first and last name from the SMF realName field
        if (count(explode(" ", $name)) > 1) list($fname,$lname) = explode(" ",$name);
        else {
            $fname = $name;
            $lname = "";
        }
		$email_exists = $wpdb->get_row("SELECT user_email FROM ".$wpdb->users." WHERE user_email = '". $email . "'");
		if (!$email_exists) {
		    // import the user since their e-mail doesn't exist
			//list($fname,$lname) = split(" ",$usr['realName']);
		    $user_id = wp_insert_user(array(
				"user_login" => $login_name,
                                "first_name" => $fname,
                                "last_name" => $lname,
                                "user_email" => $email,
                                "user_pass" => md5(date('s').rand(100,999))//this doesn't work if we're not doing it on login, but it should pick it up when the user logs in
			)
		    );
		    if ($user_id) ++$sync_count;
			//self::syncprofile($user_id, true);
		}		
	    }
	}
	return $sync_count;
    }

    /* checklogin
     * @public
     * Checks if a user is logged into SMF, and if they are, attempts to log them in to
     * WordPress as well
     */
    function checklogin() {
	if (!self::$bridge_active) return;
	global $smf_user_info,$scheme,$auth_cookie_name;
	if (smf_authenticateUser()) {
		if ($tgt_user = get_user_by('login', $smf_user_info['username']) == false) {
		    // The user does not exist in the WP database - let's sync and try again
			//if (self::syncusers() > 0)
			$tgt_user = get_user_by('login', $smf_user_info['username']);
		}
        
		if ($tgt_user->ID) {
			wp_set_current_user($tgt_user->ID,$tgt_user->user_login);
			// And set a cookie just in case
			$expiration = time() + 172800;
			$cookie_data = $tgt_user->user_login . '|' . $expiration;
			$key = wp_hash($tgt_user->user_login . '|' . $expiration,'logged_in');
			$cookie_data .= hash_hmac('md5',$tgt_user->user_login . '|' . $expiration,$key);
			$auth_cookie = wp_generate_auth_cookie($tgt_user->ID, $expiration);
			$logged_in_cookie = wp_generate_auth_cookie($tgt_user->ID, $expiration, 'logged_in');
			setcookie($auth_cookie_name, $auth_cookie, $expiration, PLUGINS_COOKIE_PATH, COOKIE_DOMAIN);
			setcookie($auth_cookie_name, $auth_cookie, $expiration, ADMIN_COOKIE_PATH, COOKIE_DOMAIN);
			setcookie(LOGGED_IN_COOKIE, $cookie_data, $expiration, COOKIEPATH, COOKIE_DOMAIN);	
			smf_logOnline('WordPress');
			self::syncprofile($tgt_user->ID,true);
		}
	} else {
		self::login();
	}
    }

    /* import_auth
     * @public
     * Syncs passwords on a login attempt both to and from WP - this is because SMF
     * uses an entirely different method of storing passwords...
     */
    function import_auth($user, $username, $password) {
        if($username == '' || $password == '') return;
        global $wpdb;
        $wp_user = get_user_by('login',$username);
        if (!function_exists('smf_authenticate_password'))
        self::load();
        if (wp_check_password($password, $wp_user->user_pass, $wp_user->ID) AND $wp_user) {
            // Sync the password into SMF if necessary
            if (!smf_authenticate_password($username,$password)) {
                smf_ChangePassword($username, $password);
            }
            return $wp_user;
        } elseif (smf_authenticate_password($username,$password) AND $wp_user) {
            _log('password authenticated with SMF');
            // Sync the password into WordPress
            wp_set_password($password, $wp_user->ID);
            return $wp_user;
        } elseif (smf_authenticate_password($username,$password)) {
            _log('authenticated with SMF but didn\'t find in wp');
            // This user must not be in WP, let's sync users up and try again
            //if (self::syncusers() == 0) return;
            //self::import_auth($username,$password);

            $smf_cxn = mysql_connect(self::$smf_dbopts['host'],self::$smf_dbopts['user'],self::$smf_dbopts['pass']);
            $SQL = "SELECT memberName, emailAddress,realName FROM ".self::$smf_dbopts['prefix']."members WHERE UPPER(memberName)=UPPER('$username') LIMIT 1";
            if (!$rs = mysql_query($SQL,$smf_cxn)) {
                // Since this is not a critical step, we'll just throw a warning instead
                // of bombing the entire app...
                trigger_error(mysql_error(),E_USER_ERROR);
                return;
            }
            list($login_name,$email,$name) = mysql_fetch_array($rs);
            // Grab first and last name from the SMF realName field
            if (count(explode(" ", $name)) > 1) list($fname,$lname) = explode(" ",$name);
            else {
                $fname = $name;
                $lname = "";
            }
		    $user_id = wp_insert_user(array(
				"user_login" => $login_name,
                "first_name" => $fname,
                "last_name" => $lname,
                "user_email" => $email,
                "user_pass" => md5(date('s').rand(100,999))//this doesn't work if we're not doing it on login, but it should pick it up when the user logs in
			)
		    );
            $new_user = get_userdata($user_id);
            return $new_user;

        }
    }
}

if (!function_exists('add_action')) exit;
/* Associate the necessary action and filter hooks */
add_action('admin_menu',array('smf_bridge','add_menu'));
//add_action('user_register',array('smf_bridge','register')); // Takes 1 argument, userID
add_action('profile_update',array('smf_bridge','syncprofile'));
add_action('personal_options_update',array('smf_bridge','syncprofile'));
add_action('plugins_loaded',array('smf_bridge','load'));
//add_action('set_current_user',array('smf_bridge','checklogin'));
add_filter('authenticate',array('smf_bridge','import_auth'),40,3);
add_filter('validate_username',array('smf_bridge','uservalid'),10,2);
?>
