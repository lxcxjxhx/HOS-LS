'status': True,
}
)
@blueprint.route(
'/query_tool/download/<int:trans_id>',
methods=["POST"],
endpoint='query_tool_download'
)
@pga_login_required
def start_query_download_tool(trans_id):
    status_ok, error_info, conn_obj, transaction, session_ref = check_transaction_status(trans_id)
    if not status_ok or conn_obj is None or transaction is None or session_ref is None:
        return internal_server_error(
            errormsg=TRANSACTION_STATUS_CHECK_FAILED
        )
    payload = request.values if request.values else request.get_json(silent=True)
    if payload is None:
        return make_json_response(
            status=410,
            success=0,
            errormsg=gettext("Could not find the required parameter (query).")
        )
    try:
        sql_text = None  
        query_flag = payload.get('query_commited', False)  
        for k, v in payload.items():  
            if k == 'query':
                sql_text = v
            if k == 'query_commited':
                # Safely convert string values to boolean
                if isinstance(v, str):
                    query_flag = v.lower() in ['true', '1', 'yes']
                else:
                    query_flag = bool(v)
        if not sql_text:
            sql_text = transaction.get_sql(conn_obj)
        if sql_text and query_flag:
            conn_obj.execute_async(sql_text)
            status_exec, generator_func, connection = conn_obj.execute_on_server_as_csv(records=10) 
            if not status_exec:
                return make_json_response(
                    data={'status': status_exec, 'result': generator_func}
                )
            result_stream = Response(
                generator_func(
                    connection,
                    transaction,
                    quote=blueprint.csv_quoting.get(),
                    quote_char=blueprint.csv_quote_char.get(),
                    field_separator=blueprint.csv_field_separator.get(),
                    replace_nulls_with=blueprint.replace_nulls_with.get()
                ),
                mimetype='text/csv' if blueprint.csv_field_separator.get() == ',' else 'text/plain'
            )
            import time
            file_ext = 'csv' if blueprint.csv_field_separator.get() == ',' else 'txt'  
            fname = payload['filename'] if payload.get('filename', '') != "" else \
                '{0}.{1}'.format(int(time.time()), file_ext)