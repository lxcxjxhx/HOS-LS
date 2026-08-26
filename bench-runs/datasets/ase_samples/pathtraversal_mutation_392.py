root[len(cfg.wiki_directory + "/"):] + "/" + item)[0]
103                             info = {'doc': item,
'url': url,
'folder': folder,
'folder_url': root[len(cfg.wiki_directory + "/"):]}
found.append(info)
app.logger.info(f"Found '{search_term}' in '{item}'")
except Exception as e:
app.logger.error(f"Error while searching >>> {str(e)}")
112         return render_template('search.html', zoekterm=found, system=SYSTEM_SETTINGS)
114     
def fetch_page_name() -> str:
page_name = request.form['PN']
if page_name[-4:] == "{id}":
page_name = f"{page_name[:-4]}{uuid.uuid4().hex}"
return page_name
121     
@app.route('/list/', methods=['GET'])
def list_full_wiki():
return list_wiki("")
126     
@app.route('/list/<path:folderpath>/', methods=['GET'])
def list_wiki(folderpath):
folder_list = []
app.logger.info("Showing >>> 'all files'")
>>>     for root, subfolder, files in os.walk(os.path.join(cfg.wiki_directory, folderpath)):
>>>         if root[-1] == '/':
>>>             root = root[:-1]
>>>         for item in files:
>>>             path = os.path.join(root, item)
>>>             mtime = os.path.getmtime(os.path.join(root, item))
>>>             if os.path.join(cfg.wiki_directory, '.git') in str(path):
>>>                 # We don't want to search there
>>>                 app.logger.debug(f"skipping {path}: is git file")
>>>                 continue
>>>             if os.path.join(cfg.wiki_directory, cfg.images_route) in str(path):
>>>                 # Nothing interesting there too
>>>                 continue
>>> 
>>>             folder = root[len(cfg.wiki_directory + "/"):]
>>>             if folder == "":
>>>                 if item == cfg.homepage:
>>>                     continue
>>>                 url = os.path.splitext(
>>>                     root[len(cfg.wiki_directory + "/"):] + "/" + item)[0]
>>>             else:
>>>                 url = "/" + \
>>>                     os.path.splitext(
>>>                         root[len(cfg.wiki_directory + "/"):] + "/" + item)[0]
>>> 
>>>             info = {'doc': item,
>>>                     'url': url,
>>>                     'folder': folder,
>>>                     'folder_url': folder,
>>>                     'mtime': mtime,
>>>                     }
>>>             folder_list.append(info)
164         if SYSTEM_SETTINGS['listsortMTime']:
folder_list.sort(key=lambda x: x["mtime"], reverse=True)
else:
folder_list.sort(key=lambda x: (str(x["url"]).casefold()))
169         return render_template('list_files.html', list=folder_list, folder=folderpath, system=SYSTEM_SETTINGS)
171     
@app.route('/<path:file_page>', methods=['POST', 'GET'])
def file_page(file_page):
if request.method == 'POST':
return search()
else:
html = ""
mod = ""
folder = ""
181             if "favicon" not in file_page:  # if the GET request is not for the favicon
try:
md_file_path = os.path.join(cfg.wiki_directory, file_page + ".md")
# latex = pypandoc.convert_file("wiki/" + file_page + ".md", "tex", format="md")
# html = pypandoc.convert_text(latex,"html5",format='tex', extra_args=["--mathjax"])
187                     app.logger.info(f"Converting to HTML with pandoc >>> '{md_file_path}' ...")
html = pypandoc.convert_file(md_file_path, "html5",
format='md', extra_args=["--mathjax"], filters=['pandoc-xnos'])
html = clean_html(html)
mod = "Last modified: %s" % time.ctime(os.path.getmtime(md_file_path))
folder = file_page.split("/")