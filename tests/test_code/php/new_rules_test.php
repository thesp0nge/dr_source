<?php
// VULNERABLE: INSECURE_CONFIG
display_errors = On;

$page = $_GET['page'];
// VULNERABLE: UNSAFE_FILE_INCLUDE
include($page);

$id = $_POST['id'];
// VULNERABLE: LOG_INJECTION
error_log("User ID failed login: " . $id);
?>
