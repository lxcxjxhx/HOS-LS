function get_filename_wo_extension( $filename )
{
$pos = strrpos( $filename, '.' );
return ($pos===false) ? $filename : substr( $filename, 0, $pos);
}
127     /**
* returns an array contening sub-directories, excluding ".svn"
*
* @param string $dir
* @return array
*/
function get_dirs($directory)
{
$sub_dirs = array();
if ($opendir = opendir($directory))
{
while ($file = readdir($opendir))
{
if ($file != '.'
and $file != '..'
and is_dir($directory.'/'.$file)
and $file != '.svn')
{
array_push($sub_dirs, $file);
}
}
closedir($opendir);
}
return $sub_dirs;
>>> }
>>> 
>>> define('MKGETDIR_NONE', 0);
>>> define('MKGETDIR_RECURSIVE', 1);
>>> define('MKGETDIR_DIE_ON_ERROR', 2);
>>> define('MKGETDIR_PROTECT_INDEX', 4);
>>> define('MKGETDIR_PROTECT_HTACCESS', 8);
>>> define('MKGETDIR_DEFAULT', 7);
>>> /**
>>>  * creates directory if not exists; ensures that directory is writable
>>>  * @param:
>>>  *  string $dir
>>>  *  int $flags combination of MKGETDIR_xxx
>>>  * @return bool false on error else true
>>>  */
>>> function mkgetdir($dir, $flags=MKGETDIR_DEFAULT)
>>> {
>>>   if ( !is_dir($dir) )
>>>   {
>>>     if (substr(PHP_OS, 0, 3) == 'WIN')
>>>     {
>>>       $dir = str_replace('/', DIRECTORY_SEPARATOR, $dir);
>>>     }
>>>     $umask = umask(0);
>>>     $mkd = @mkdir($dir, 0755, ($flags&MKGETDIR_RECURSIVE) ? true:false );
>>>     umask($umask);
>>>     if ($mkd==false)
>>>     {
>>>       !($flags&MKGETDIR_DIE_ON_ERROR) or fatal_error( "$dir ".l10n('no write access'));
>>>       return false;
>>>     }
>>>     if( $flags&MKGETDIR_PROTECT_HTACCESS )
>>>     {
>>>       $file = $dir.'/.htaccess';
>>>       file_exists($file) or @file_put_contents( $file, 'deny from all' );
>>>     }
>>>     if( $flags&MKGETDIR_PROTECT_INDEX )
>>>     {
>>>       $file = $dir.'/index.htm';
>>>       file_exists($file) or @file_put_contents( $file, 'Not allowed!' );
>>>     }
>>>   }
>>>   if ( !is_writable($dir) )
>>>   {
>>>     !($flags&MKGETDIR_DIE_ON_ERROR) or fatal_error( "$dir ".l10n('no write access'));
>>>     return false;
>>>   }
>>>   return true;
>>> }
>>> 
>>> /**
>>>  * returns thumbnail directory name of input diretoty name
>>>  * make thumbnail directory is necessary
>>>  * set error messages on array messages
>>>  *
>>>  * @param:
>>>  *  string $dirname
*  arrayy $errors
* @return bool false on error else string directory name
*/
function mkget_thumbnail_dir($dirname, &$errors)
{
global $conf;
215       $tndir = $dirname.'/'.$conf['dir_thumbnail'];
if (! mkgetdir($tndir, MKGETDIR_NONE) )
{
array_push($errors,
'['.$dirname.'] : '.l10n('no write access'));
return false;
}
return $tndir;
}
225     /* Returns true if the string appears to be encoded in UTF-8. (from wordpress)
* @param string Str
*/
function seems_utf8($Str) { # by bmorel at ssi dot fr
for ($i=0; $i<strlen($Str); $i++) {
if (ord($Str[$i]) < 0x80) continue; # 0bbbbbbb
elseif ((ord($Str[$i]) & 0xE0) == 0xC0) $n=1; # 110bbbbb
elseif ((ord($Str[$i]) & 0xF0) == 0xE0) $n=2; # 1110bbbb
elseif ((ord($Str[$i]) & 0xF8) == 0xF0) $n=3; # 11110bbb
elseif ((ord($Str[$i]) & 0xFC) == 0xF8) $n=4; # 111110bb
elseif ((ord($Str[$i]) & 0xFE) == 0xFC) $n=5; # 1111110b
else return false; # Does not match any model
for ($j=0; $j<$n; $j++) { # n bytes matching 10bbbbbb follow ?