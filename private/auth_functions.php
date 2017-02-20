<?php

  // Will perform all actions necessary to log in the user
  // Also protects user from session fixation.
  function log_in_user($user) {
    // regenrate the session ID to provent Session Fixation Attack
    session_regenerate_id();
    // store the user's ID in the session data (as "user_id").
    $_SESSION['user_id'] = $user['id'];
    // store the user's last login time in the session data (as "last_login").
    $_SESSION['last_login'] = time();
    $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
    return true;
  }
  // A one-step function to destroy the current session
  function destroy_current_session() {
    
    // destroy the session file completely
    unset($_SESSION['last_login']);
    unset($_SESSION['user_agent']);
    session_unset();
    session_destroy();
  }
  // Performs all actions necessary to log out a user
  function log_out_user() {
    unset($_SESSION['user_id']);
    destroy_current_session();
    return true;
  }
  // Determines if the request should be considered a "recent"
  // request by comparing it to the user's last login time.
  function last_login_is_recent() {
    if(!isset($_SESSION['last_login'])) { return false; }
    return (($_SESSION['last_login'] +  60 * 60 * 24) >= time());
  }
  // Checks to see if the user-agent string of the current request
  // matches the user-agent string used when the user last logged in.
  function user_agent_matches_session() {
    // added code to determine if user agent matches session
    if(!isset($_SERVER['HTTP_USER_AGENT'])){return false;}
    if(!isset($_SESSION['user_agent'])){return false;}
    return ($_SERVER['HTTP_USER_AGENT'] === $_SESSION['user_agent']);
  }
  // Inspects the session to see if it should be considered valid.
  function session_is_valid() {
    if(!last_login_is_recent()) { return false; }
    if(!user_agent_matches_session()) { return false; }
    return true;
  }
  // is_logged_in() contains all the logic for determining if a
  // request should be considered a "logged in" request or not.
  // It is the core of require_login() but it can also be called
  // on its own in other contexts (e.g. display one link if a user
  // is logged in and display another link if they are not)
  function is_logged_in() {
    // Having a user_id in the session serves a dual-purpose:
    // - Its presence indicates the user is logged in.
    // - Its value tells which user for looking up their record.
    if(!isset($_SESSION['user_id'])) { return false; }
    if(!session_is_valid()) { return false; }
    return true;
  }
  // Call require_login() at the top of any page which needs to
  // require a valid login before granting acccess to the page.
  function require_login() {
    if(!is_logged_in()) {
      destroy_current_session();
      redirect_to(url_for('/staff/login.php'));
    } else {
      // Do nothing, let the rest of the page proceed
    }
  }

  //function to record a failed login
  function record_failed_login($username) {
    $sql_date = date("Y-m-d H:i:s");
    $fl_result = find_failed_login($username);
    $failed_login = db_fetch_assoc($fl_result);
    if(!$failed_login) {
      $failed_login = [
        'username' => $username,
        'count' => 1,
        'last_attempt' => $sql_date
      ];
      insert_failed_login($failed_login);
    } else {
      $failed_login['count'] = $failed_login['count'] + 1;
      $failed_login['last_attempt'] = $sql_date;
      update_failed_login($failed_login);
    }
    return true;
  }

  // returns the lockout minutes remaining for a user, or 0 if they have not
  // reached the lockout threshold
  function throttle_time($username) {
    $threshold = 5;
    $lockout = 60 * 5; // in seconds
    $fl_result = find_failed_login($username);
    $failed_login = db_fetch_assoc($fl_result);
    if(!isset($failed_login)) { return 0; }
    if($failed_login['count'] < $threshold) { return 0; }
    $last_attempt = strtotime($failed_login['last_attempt']);
    $since_last_attempt = time() - $last_attempt;
    $seconds_remaining = $lockout - $since_last_attempt;
    $minutes_remaining = ceil($seconds_remaining/60);
    if($seconds_remaining <= 0) {
      reset_failed_login($username);
      return 0;
    } else {
      return $minutes_remaining;
    }
  }
  // hashes a given password using bcrypt with an optionally specified. emulates password_hash
  function my_password_hash($password, $cost=10) {
    $hash_format = "$2y" . $cost . "$";
    $salt = make_salt();
    return crypt($password, $hash_format.$salt);
  }
  // verifies that the bcrypt hash of a given password matches a given hash
  function my_password_verify($password, $hashed_password) {
    return crypt($password, $hashed_password) === $hashed_password;
  }
  // returns a random string of an optionally given length
  function random_string($length=22) {
    // random_bytes requires an integer larger than 1
    $length = max(1, (int) $length);
    // generates a longer string than needed
    $rand_str = base64_encode(random_bytes($length));
    // substr cuts it to the correct size
    return substr($rand_str, 0, $length);
  }
  // creates a salt appropriate for the bcrypt encryption algorithm
  function make_salt() {
    // default length is 22
    $rand_str = random_string(22);
    // bcrypt doesn't like '+'
    $salt = strtr($rand_str, '+', '.');
    return $salt;
  }
  // creates a password of upper and lower case characters, numbers, and symbols
  function generate_strong_password($length=12) {
    $possible_chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*?';
    $characters = array('0123456789', 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', '!@#$%^&*?');
    $password_chars = array();
    //keep track of the index of the initial 4 characters
    $initial_fill = array();
    $index = random_int(0, $length - 1);
    for ($char_filled = 0; $char_filled < 4; $char_filled++){
      // make sure the new index is not filled already
      while (in_array($index, $initial_fill)){
        $index = random_int(0, $length - 1);
      }
      $initial_fill[$char_filled] = $index;
      $possible_part = $characters[$char_filled];
      $password_chars[$index] = $possible_part[random_int(0, strlen($possible_part) - 1)];
    }
    for ($i = 0; $i < $length; $i++) {
      if (!in_array($i, $initial_fill)){
        $password_chars[$i] .= $possible_chars[random_int(0, strlen($possible_chars) - 1)];
      }
    }
    $password  = implode($password_chars);
    return $password;
  }

?>
