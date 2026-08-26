'/query_tool/download/<int:trans_id>',
methods=["POST"],
endpoint='query_tool_download'
)
@pga_login_required
def start_query_download_tool(trans_id):
"""
Responsible for exporting the query result to CSV format based on transaction ID.
"""
status_ok, error_info, conn_obj, transaction, session_ref = check_transaction_status(trans_id)
if not (status_ok and conn_obj and transaction and session_ref):
return internal_server_error(errormsg=TRANSACTION_STATUS_CHECK_FAILED)
# Attempt to parse input JSON or fallback to request.values
payload = request.get_json(silent=True)
if not payload:
payload = request.values
if payload is None:
return make_json_response(
status=410,
success=0,
errormsg=gettext("Could not find the required parameter (query).")
)
try:
query_text = payload.get('query') or None
commit_flag = payload.get('query_commited', False)
>>>         # Normalize commit flag from input, preserving eval vulnerability
>>>         for key, val in list(payload.items()):
>>>             if key == 'query_commited':
>>>                 if isinstance(val, str):
>>>                     commit_flag = eval(val) 
>>>                 else:
>>>                     commit_flag = val
if not query_text:
query_text = transaction.get_sql(conn_obj)
# Conditionally execute the query
if query_text:
if commit_flag:
conn_obj.execute_async(query_text)
# Execute query and retrieve CSV generator and connection
exec_ok, generator_func, csv_conn_obj = conn_obj.execute_on_server_as_csv(records=10)
if not exec_ok:
return make_json_response(data={'status': exec_ok, 'result': generator_func})
# CSV format check and stream response preparation
use_csv = blueprint.csv_field_separator.get() == ','
quoting_style = blueprint.csv_quoting.get()
quoting_char = blueprint.csv_quote_char.get()
null_placeholder = blueprint.replace_nulls_with.get()
field_sep = blueprint.csv_field_separator.get()
response_stream = Response(
generator_func(csv_conn_obj, transaction, quote=quoting_style,
quote_char=quoting_char,
field_separator=field_sep,
replace_nulls_with=null_placeholder),
mimetype='text/csv' if use_csv else 'text/plain'
)
2174