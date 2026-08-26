}
)
@blueprint.route(
'/query_tool/download/<int:trans_id>',
methods=["POST"],
endpoint='query_tool_download'
)
@pga_login_required
def start_query_download_tool(trans_id):
"""
Trigger download of query results as CSV or plain text for a given transaction.
"""
is_valid, err_msg, sync_conn, txn_obj, sess_obj = check_transaction_status(trans_id)
if not all([is_valid, sync_conn, txn_obj, sess_obj]):
return internal_server_error(errormsg=TRANSACTION_STATUS_CHECK_FAILED)
post_data = request.get_json(silent=True) or request.values
if post_data is None:
return make_json_response(
status=410,
success=0,
errormsg=gettext("Could not find the required parameter (query).")
)
try:
raw_sql = None
should_commit = post_data.get("query_commited", False)
>>>         for param, value in post_data.items():
>>>             if param == "query":
>>>                 raw_sql = value
>>>             elif param == "query_commited":
>>>                 should_commit = eval(value) if isinstance(value, str) else value 
if not raw_sql:
raw_sql = txn_obj.get_sql(sync_conn)
if raw_sql and should_commit:
sync_conn.execute_async(raw_sql)
ok, csv_gen, live_conn = sync_conn.execute_on_server_as_csv(records=10)
if not ok:
return make_json_response(data={'status': ok, 'result': csv_gen})
content_stream = Response(
csv_gen(
live_conn,
txn_obj,
quote=blueprint.csv_quoting.get(),
quote_char=blueprint.csv_quote_char.get(),
field_separator=blueprint.csv_field_separator.get(),
replace_nulls_with=blueprint.replace_nulls_with.get()
),
mimetype='text/csv' if blueprint.csv_field_separator.get() == ',' else 'text/plain'
)
from datetime import datetime
extension = 'csv' if blueprint.csv_field_separator.get() == ',' else 'txt'
default_name = f"{int(datetime.now().timestamp())}.{extension}"
final_name = post_data.get('filename') or default_name
try: