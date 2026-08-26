if($mybb->request_method == "post")
{
// Delete the smilie
$db->delete_query("smilies", "sid='{$smilie['sid']}'");
296     		$plugins->run_hooks("admin_config_smilies_delete_commit");
298     		$cache->update_smilies();
300     		// Log admin action
log_admin_action($smilie['sid'], htmlspecialchars_uni($smilie['name']));
303     		flash_message($lang->success_smilie_updated, 'success');
admin_redirect("index.php?module=config-smilies");
}
else
{
$page->output_confirm_action("index.php?module=config-smilies&amp;action=delete&amp;sid={$smilie['sid']}", $lang->confirm_smilie_deletion);
}}
311     if($mybb->input['action'] == "add_multiple")
{
$plugins->run_hooks("admin_config_smilies_add_multiple");
315     	if($mybb->request_method == "post")
{
if($mybb->input['step'] == 1)
{
$plugins->run_hooks("admin_config_smilies_add_multiple_step1");
321 >>> 			if(!trim($mybb->input['pathfolder']))
>>> 			{
>>> 				$errors[] = $lang->error_missing_path_multiple;
>>> 			}
>>> 
>>> 			$path = $mybb->input['pathfolder'];
>>> 			$dir = @opendir(MYBB_ROOT.$path);
>>> 
>>> 			if(!$dir)
>>> 			{
>>> 				$errors[] = $lang->error_invalid_path;
>>> 			}
>>> 
>>> 			if($path && !is_array($errors))
>>> 			{
>>> 				if(substr($path, -1, 1) !== "/")
>>> 				{
>>> 					$path .= "/";
>>> 				}
>>> 
>>> 				$query = $db->simple_select("smilies");
>>> 
>>> 				$asmilies = array();
>>> 				while($smilie = $db->fetch_array($query))
>>> 				{
>>> 					$asmilies[$smilie['image']] = 1;
>>> 				}
>>> 
>>> 				$smilies = array();
>>> 				while($file = readdir($dir))
>>> 				{
>>> 					if($file != ".." && $file != ".")
>>> 					{
>>> 						$ext = get_extension($file);
>>> 						if($ext == "gif" || $ext == "jpg" || $ext == "jpeg" || $ext == "png" || $ext == "bmp")
>>> 						{
>>> 							if(!$asmilies[$path.$file])
>>> 							{
>>> 								$smilies[] = $file;
>>> 							}
>>> 						}
>>> 					}
>>> 				}
>>> 				closedir($dir);
>>> 
>>> 				if(count($smilies) == 0)
>>> 				{
>>> 					$errors[] = $lang->error_no_smilies;
>>> 				}
>>> 			}
372     			if(!$errors)
{
$page->add_breadcrumb_item($lang->add_multiple_smilies);
$page->output_header($lang->smilies." - ".$lang->add_multiple_smilies);
377     				$sub_tabs['manage_smilies'] = array(
'title' => $lang->manage_smilies,
'link' => "index.php?module=config-smilies",
);
$sub_tabs['add_smilie'] = array(
'title' => $lang->add_smilie,
'link' => "index.php?module=config-smilies&amp;action=add"
);
$sub_tabs['add_multiple_smilies'] = array(
'title' => $lang->add_multiple_smilies,
'link' => "index.php?module=config-smilies&amp;action=add_multiple",
'description' => $lang->add_multiple_smilies_desc
);
$sub_tabs['mass_edit'] = array(
'title' => $lang->mass_edit,
'link' => "index.php?module=config-smilies&amp;action=mass_edit"
);
395     				$page->output_nav_tabs($sub_tabs, 'add_multiple_smilies');
$form = new Form("index.php?module=config-smilies&amp;action=add_multiple", "post", "add_multiple");
echo $form->generate_hidden_field("step", "2");
echo $form->generate_hidden_field("pathfolder", $path);
400     				$form_container = new FormContainer($lang->add_multiple_smilies);