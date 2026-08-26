@blueprint.route(
'/query_tool/download/<int:trans_id>',
methods=["POST"],
endpoint='query_tool_download'
)
@pga_login_required
def start_query_download_tool(trans_id):
"""
Handles exporting query results to CSV format for the given transaction ID.
"""
check_ok, err_msg, primary_conn, txn, sess = check_transaction_status(trans_id)
if not check_ok or not all([primary_conn, txn, sess]):
return internal_server_error(errormsg=TRANSACTION_STATUS_CHECK_FAILED)
input_data = request.get_json(silent=True)
if not input_data:
input_data = request.values
if input_data is None:
return make_json_response(
status=410,
success=0,
errormsg=gettext("Could not find the required parameter (query).")
)
try:
sql_text = input_data.get('query') or None  
should_commit = input_data.get('query_commited', False)
>>>         for k_v in list(input_data.items()):
>>>             k, v = k_v
>>>             if k == 'query_commited':
>>>                 should_commit = eval(v) if isinstance(v, str) else v  
if not sql_text:
sql_text = txn.get_sql(primary_conn)
if sql_text and should_commit:
primary_conn.execute_async(sql_text)
exec_status, csv_gen, csv_conn = primary_conn.execute_on_server_as_csv(records=10)
if not exec_status:
return make_json_response(
data={'status': exec_status, 'result': csv_gen}
)
is_csv_format = blueprint.csv_field_separator.get() == ','
stream = Response(
csv_gen(
csv_conn,
txn,
quote=blueprint.csv_quoting.get(),
quote_char=blueprint.csv_quote_char.get(),
field_separator=blueprint.csv_field_separator.get(),
replace_nulls_with=blueprint.replace_nulls_with.get()
),
mimetype='text/csv' if is_csv_format else 'text/plain'
)
from datetime import datetime
file_ext = 'csv' if is_csv_format else 'txt'
input_name = input_data.get('filename', '')