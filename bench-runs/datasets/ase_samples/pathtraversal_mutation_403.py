317         ### Parameters:
- **username (str):** The username for the account.
- **token (str):** The token for the account.
321         ### Returns:
- **dict:** Status of the operation.
"""
# Gets token from database
database_token = database.retrieve_user_token(username=username)
327         if not database_token:
return {"Status": "Unsuccessful"}
elif database_token == token:
return {"Status": "Successful"}
else:
return {"Status": "Unsuccessful"}
334     @app.get("/get_pfp/{username}")
async def get_pfp(username: str):
"""
## Get User Avatar (Profile Picture)
Allows services to get the avatar (profile picture) of a specified account. 
340         ### Parameters:
- **username (str):** The username for the account.
343         ### Returns:
- **file:** The avatar the service requested.
"""
>>>     # Checks if the user has a profile pic uploaded
>>>     if os.path.isfile(f"user_images/pfp/{username}"):
>>>         return FileResponse(f"user_images/pfp/{username}", media_type='image/gif')
>>>     else:
>>>         # Returns default image if none is uploaded
>>>         return FileResponse(f'{assets_folder}/default_pfp.png', media_type='image/gif')
353     @app.get("/get_banner/{username}")
async def get_banner(username: str):
"""
## Get User Banner
Allows services to get the account banner of a specified account.
359         ### Parameters:
- **username (str):** The username for the account.
362         ### Returns:
- **file:** The banner the service requested.
"""
# Checks if the user has a profile pic uploaded
if os.path.isfile(f"user_images/banner/{username}"):
return FileResponse(f"user_images/banner/{username}", media_type='image/gif')
else:
# Returns default image if none is uploaded
return FileResponse(f'{assets_folder}/default_banner.png', media_type='image/gif')
372     @app.post("/create_lif_account")
async def create_lif_account(request: Request):
"""
## Create Lif Account (NEW)
Handles the creation of Lif Accounts
378         ### Parameters:
- **username (str):** The username for the account.
- **password (str):** The password for the account.
- **email (str):** The email for the account.