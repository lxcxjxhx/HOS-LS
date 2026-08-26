print(query_request.limit)
try:
return Result.succ(
knowledge_service_handler.query_graph(
space_name=space_name, limit=query_request.limit
)
)
except Exception as e:
return Result.failed(code="E000X", msg=f"get graph vis error {e}")
321     
@router.post("/knowledge/{space_name}/document/delete")
def document_delete(space_name: str, query_request: DocumentQueryRequest):
print(f"/document/list params: {space_name}, {query_request}")
try:
return Result.succ(
knowledge_service_handler.delete_document(space_name, query_request.doc_name)
)
except Exception as e:
return Result.failed(code="E000X", msg=f"document delete error {e}")
332     
@router.post("/knowledge/{space_name}/document/upload")
async def document_upload(
space_name: str,
doc_name: str = Form(...),
doc_type: str = Form(...),
doc_file: UploadFile = File(...),
):
print(f"/document/upload params: {space_name}")
>>>     try:
>>>         if doc_file:
>>>             if not os.path.exists(os.path.join(KNOWLEDGE_UPLOAD_ROOT_PATH, space_name)):
>>>                 os.makedirs(os.path.join(KNOWLEDGE_UPLOAD_ROOT_PATH, space_name))
>>>             # We can not move temp file in windows system when we open file in context of `with`
>>>             tmp_fd, tmp_path = tempfile.mkstemp(
>>>                 dir=os.path.join(KNOWLEDGE_UPLOAD_ROOT_PATH, space_name)
>>>             )
>>>             with os.fdopen(tmp_fd, "wb") as tmp:
>>>                 tmp.write(await doc_file.read())
>>>             shutil.move(
>>>                 tmp_path,
>>>                 os.path.join(KNOWLEDGE_UPLOAD_ROOT_PATH, space_name, doc_file.filename),
>>>             )
>>>             request = KnowledgeDocumentRequest()
>>>             request.doc_name = doc_name
>>>             request.doc_type = doc_type
>>>             request.content = os.path.join(
>>>                 KNOWLEDGE_UPLOAD_ROOT_PATH, space_name, doc_file.filename
>>>             )
>>>             space_res = knowledge_service_handler.get_knowledge_space(
>>>                 KnowledgeSpaceRequest(name=space_name)
>>>             )
>>>             if len(space_res) == 0:
>>>                 # create default space
>>>                 if "default" != space_name:
>>>                     raise Exception(f"you have not create your knowledge space.")
>>>                 knowledge_service_handler.create_knowledge_space(
>>>                     KnowledgeSpaceRequest(
>>>                         name=space_name,
>>>                         desc="first db-gpt rag application",
>>>                         owner="dbgpt",
>>>                     )
>>>                 )
>>>             return Result.succ(
>>>                 knowledge_service_handler.create_knowledge_document(
>>>                     space=space_name, request=request
>>>                 )
>>>             )
>>>         return Result.failed(code="E000X", msg=f"doc_file is None")
>>>     except Exception as e:
>>>         return Result.failed(code="E000X", msg=f"document add error {e}")
384     
@router.post("/knowledge/{space_name}/document/sync")
async def document_sync(
space_name: str,
request: DocumentSyncRequest,
service: Service = Depends(get_rag_service),
):
logger.info(f"Received params: {space_name}, {request}")
try:
space = service.get({"name": space_name})
if space is None:
return Result.failed(code="E000X", msg=f"space {space_name} not exist")
if request.doc_ids is None or len(request.doc_ids) == 0:
return Result.failed(code="E000X", msg="doc_ids is None")
sync_request = KnowledgeSyncRequest(
doc_id=request.doc_ids[0],
space_id=str(space.id),
model_name=request.model_name,
)
sync_request.chunk_parameters = ChunkParameters(
chunk_strategy="Automatic",
chunk_size=request.chunk_size or 512,
chunk_overlap=request.chunk_overlap or 50,
)
doc_ids = await service.sync_document(requests=[sync_request])
return Result.succ(doc_ids)
except Exception as e:
return Result.failed(code="E000X", msg=f"document sync error {e}")
 412