def index_page():
"""Load the index page"""
try:
if not flask_login.current_user.index_page:
return home()
elif flask_login.current_user.index_page == 'landing':
return home()
else:
if flask_login.current_user.is_authenticated:
if flask_login.current_user.index_page == 'live':
return redirect(url_for('routes_page.page_live'))
elif flask_login.current_user.index_page == 'dashboard':
return redirect(url_for('routes_dashboard.page_dashboard_default'))
elif flask_login.current_user.index_page == 'info':
return redirect(url_for('routes_page.page_info'))
return redirect(url_for('routes_page.page_live'))
except:
log_handler.error("User may not be logged in. Clearing cookie auth.")
return clear_cookie_auth()
107     @blueprint.route('/settings', methods=('GET', 'POST'))
@flask_login.login_required
def page_settings():
return redirect('settings/general')
112     
@blueprint.route('/note_attachment/<filename>')
@flask_login.login_required
def send_note_attachment(filename):
"""Return a file from the note attachment directory"""
>>>     file_path = os.path.join(PATH_NOTE_ATTACHMENTS, filename)
>>>     if file_path is not None:
>>>         try:
>>>             return send_file(file_path, as_attachment=True)
>>>         except Exception:
>>>             log_handler.exception("Send note attachment")
124     
@blueprint.route('/camera/<camera_unique_id>/<img_type>/<filename>')
@flask_login.login_required
def camera_img_return_path(camera_unique_id, img_type, filename):
"""Return an image from stills or time-lapses"""
camera = Camera.query.filter(Camera.unique_id == camera_unique_id).first()
camera_path = assure_path_exists(
os.path.join(PATH_CAMERAS, '{uid}'.format(uid=camera.unique_id)))
if img_type == 'still':
if camera.path_still:
path = camera.path_still
else:
path = os.path.join(camera_path, img_type)
elif img_type == 'timelapse':
if camera.path_timelapse:
path = camera.path_timelapse
else:
path = os.path.join(camera_path, img_type)
else:
return "Unknown Image Type"
145         if os.path.isdir(path):
files = (files for files in os.listdir(path)
if os.path.isfile(os.path.join(path, files)))
else:
files = []
if filename in files:
path_file = os.path.join(path, filename)
return send_file(path_file, mimetype='image/jpeg')