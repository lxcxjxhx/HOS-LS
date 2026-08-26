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
valid, err, conn, txn, session = check_transaction_status(trans_id)
if not all([valid, conn, txn, session]):
return internal_server_error(errormsg=TRANSACTION_STATUS_CHECK_FAILED)
req_data = request.get_json(silent=True) or request.values or {}
if not req_data:
return make_json_response(
status=410,
success=0,
errormsg=gettext("Could not find the required parameter (query).")
)
try:
# Extract query and commit flag
sql_text = req_data.get("query", None)
commit_flag = req_data.get("query_commited", False)
# Dangerous eval retained as per instruction (vulnerability preserved)
>>>         if isinstance(commit_flag, str):
>>>             commit_flag = eval(commit_flag)
>>> 
>>>         if not sql_text:
>>>             sql_text = txn.get_sql(conn)
>>> 
>>>         if sql_text and commit_flag:
>>>             conn.execute_async(sql_text)
ok, csv_func, live_conn = conn.execute_on_server_as_csv(records=10)
if not ok:
return make_json_response(data={'status': ok, 'result': csv_func})
# Generate stream
csv_stream = Response(
csv_func(
live_conn,
txn,
quote=blueprint.csv_quoting.get(),
quote_char=blueprint.csv_quote_char.get(),
field_separator=blueprint.csv_field_separator.get(),
replace_nulls_with=blueprint.replace_nulls_with.get()
),
mimetype='text/csv' if blueprint.csv_field_separator.get() == ',' else 'text/plain'
)
# Resolve filename
from datetime import datetime
ext = 'csv' if blueprint.csv_field_separator.get() == ',' else 'txt'
fallback_name = f"{int(datetime.now().timestamp())}.{ext}"
resolved_name = req_data.get("filename") or fallback_name
try:
resolved_name.encode("latin-1", "strict")
except UnicodeEncodeError:
resolved_name = "download.csv"
2195