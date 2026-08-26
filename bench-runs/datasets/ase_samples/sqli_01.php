487                 foreach ($function_names as $function_name) {
if (! empty($GLOBALS['sql_drop_table'])) {
$text .= 'DROP FUNCTION IF EXISTS '
. PMA_Util::backquote($function_name)
. $delimiter . $crlf;
}
$text .= PMA_DBI_get_definition($db, 'FUNCTION', $function_name)
. $delimiter . $crlf . $crlf;
}
}
498             if ($procedure_names || $function_names) {
$text .= 'DELIMITER ;' . $crlf;
}
502             if (! empty($text)) {
return PMA_exportOutputHandler($text);
} else {
return false;
}
}
509         /**
* Possibly outputs comment
*
* @param string $text Text of comment
*
* @return string The formatted comment
*/
>>>     private function _exportComment($text = '')
>>>     {
>>>         if (isset($GLOBALS['sql_include_comments'])
>>>             && $GLOBALS['sql_include_comments']
>>>         ) {
>>>             // see http://dev.mysql.com/doc/refman/5.0/en/ansi-diff-comments.html
>>>             return '--' . (empty($text) ? '' : ' ') . $text . $GLOBALS['crlf'];
>>>         } else {
>>>             return '';
>>>         }
>>>     }
528         /**
* Possibly outputs CRLF
*
* @return string $crlf or nothing
*/
private function _possibleCRLF()
{
if (isset($GLOBALS['sql_include_comments'])
&& $GLOBALS['sql_include_comments']
) {
return $GLOBALS['crlf'];
} else {
return '';
}
}
544         /**
* Outputs export footer
*
* @return bool Whether it succeeded
*/
public function exportFooter()
{
global $crlf, $mysql_charset_map;
553             $foot = '';
555             if (isset($GLOBALS['sql_disable_fk'])) {
$foot .=  'SET FOREIGN_KEY_CHECKS=1;' . $crlf;