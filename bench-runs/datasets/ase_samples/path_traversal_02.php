/**
* @return void
*/
public function save(): void {
$this->load->language('catalog/download');
264     		$json = [];
266     		if (!$this->user->hasPermission('modify', 'catalog/download')) {
$json['error']['warning'] = $this->language->get('error_permission');
}
270     		foreach ($this->request->post['download_description'] as $language_id => $value) {
if ((oc_strlen(trim($value['name'])) < 3) || (oc_strlen($value['name']) > 64)) {
$json['error']['name_' . $language_id] = $this->language->get('error_name');
}
}
276     		if ((oc_strlen($this->request->post['filename']) < 3) || (oc_strlen($this->request->post['filename']) > 128)) {
$json['error']['filename'] = $this->language->get('error_filename');
}
280     		if (substr(str_replace('\\', '/', realpath(DIR_DOWNLOAD . $this->request->post['filename'])), 0, strlen(DIR_DOWNLOAD)) != DIR_DOWNLOAD) {
$json['error']['filename'] = $this->language->get('error_directory');
}
284     		if (!is_file(DIR_DOWNLOAD . $this->request->post['filename'])) {
$json['error']['filename'] = $this->language->get('error_exists');
}
288 >>> 		if (preg_match('/[^a-zA-Z0-9\/_-]|[\p{Cyrillic}]+/u', $this->request->post['filename'])) {
>>> 			$json['error']['filename'] = $this->language->get('error_filename_character');
>>> 		}
>>> 
>>> 		if ((oc_strlen($this->request->post['mask']) < 3) || (oc_strlen($this->request->post['mask']) > 128)) {
>>> 			$json['error']['mask'] = $this->language->get('error_mask');
>>> 		}
>>> 
>>> 		if (preg_match('/[^a-zA-Z0-9\/_-]|[\p{Cyrillic}]+/u', $this->request->post['mask'])) {
>>> 			$json['error']['mask'] = $this->language->get('error_mask_character');
>>> 		}
300     		if (isset($json['error']) && !isset($json['error']['warning'])) {
$json['error']['warning'] = $this->language->get('error_warning');
}
304     		if (!$json) {
$this->load->model('catalog/download');
307     			if (!$this->request->post['download_id']) {
$json['download_id'] = $this->model_catalog_download->addDownload($this->request->post);
} else {
$this->model_catalog_download->editDownload($this->request->post['download_id'], $this->request->post);
}
313     			$json['success'] = $this->language->get('text_success');
}
316     		$this->response->addHeader('Content-Type: application/json');
$this->response->setOutput(json_encode($json));
}
320     	/**
* @return void
*/
public function delete(): void {
$this->load->language('catalog/download');
326     		$json = [];
328     		if (isset($this->request->post['selected'])) {