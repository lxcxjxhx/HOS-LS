$_COOKIE[$k][$k2] = addslashes($v2);
}
@reset($_COOKIE[$k]);
}
else
{
$_COOKIE[$k] = addslashes($v);
}
}
@reset($_COOKIE);
}
}
95     //----------------------------------------------------- variable initialization
97     define('DEFAULT_PREFIX_TABLE', 'piwigo_');
99     if (isset($_POST['install']))
{
$prefixeTable = $_POST['prefix'];
}
else
{
$prefixeTable = DEFAULT_PREFIX_TABLE;
}
108     include(PHPWG_ROOT_PATH . 'include/config_default.inc.php');
@include(PHPWG_ROOT_PATH. 'local/config/config.inc.php');
defined('PWG_LOCAL_DIR') or define('PWG_LOCAL_DIR', 'local/');
112     // download database config file if exists
if (!empty($_GET['dl']) && file_exists(PHPWG_ROOT_PATH.$conf['data_location'].'pwg_'.$_GET['dl']))
{
  $dl = basename($_GET['dl']);
  if ($dl === $_GET['dl']) {
    $filename = PHPWG_ROOT_PATH.$conf['data_location'].'pwg_'.$dl;
    header('Cache-Control: no-cache, must-revalidate');
    header('Pragma: no-cache');
    header('Content-Disposition: attachment; filename="database.inc.php"');
    header('Content-Transfer-Encoding: binary');
    header('Content-Length: '.filesize($filename));
    echo file_get_contents($filename);
    unlink($filename);
    exit();
  }
} 
126     // Obtain various vars
$dbhost = (!empty($_POST['dbhost'])) ? $_POST['dbhost'] : 'localhost';
$dbuser = (!empty($_POST['dbuser'])) ? $_POST['dbuser'] : '';
$dbpasswd = (!empty($_POST['dbpasswd'])) ? $_POST['dbpasswd'] : '';
$dbname = (!empty($_POST['dbname'])) ? $_POST['dbname'] : '';
$dblayer = 'mysql';
133     $admin_name = (!empty($_POST['admin_name'])) ? $_POST['admin_name'] : '';
$admin_pass1 = (!empty($_POST['admin_pass1'])) ? $_POST['admin_pass1'] : '';
$admin_pass2 = (!empty($_POST['admin_pass2'])) ? $_POST['admin_pass2'] : '';
$admin_mail = (!empty($_POST['admin_mail'])) ? $_POST['admin_mail'] : '';
138     $is_newsletter_subscribe = true;
if (isset($_POST['install']))
{
$is_newsletter_subscribe = isset($_POST['newsletter_subscribe']);
}
144     $infos = array();
$errors = array();
147     $config_file = PHPWG_ROOT_PATH.PWG_LOCAL_DIR .'config/database.inc.php';
if (@file_exists($config_file))
{
include($config_file);
// Is Piwigo already installed ?
if (defined("PHPWG_INSTALLED"))
{
die('Piwigo is already installed');