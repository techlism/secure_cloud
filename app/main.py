# api.py
from fastapi import FastAPI, UploadFile, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from typing import Dict, Any, Optional
import tempfile
import os
from secure_storage_service import SecureStorageService

app = FastAPI(title="Secure Storage API")
storage = SecureStorageService()

@app.get("/", response_class=HTMLResponse)
async def read_root():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>API Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px; }
            .container { max-width: 800px; margin: auto; background: #fff; padding: 20px; border-radius: 5px; }
            h1 { text-align: center; color: #333; }
            form { margin-bottom: 20px; }
            input[type="text"], input[type="file"] { width: 100%; padding: 10px; margin: 5px 0 10px 0; border: 1px solid #ccc; border-radius: 4px; }
            button { background-color: #28a745; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
            button:hover { background-color: #218838; }
            .result { background: #e9ecef; padding: 10px; border-radius: 4px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>API Features</h1>
            
            <form action="/upload" method="post" enctype="multipart/form-data">
                <h2>Upload File</h2>
                <input type="file" accept=".txt" name="file">
                <button type="submit">Upload</button>
            </form>
            
            <form action="/search" method="get">
                <h2>Search</h2>
                <input type="text" name="query" placeholder="Enter search term">
                <button type="submit">Search</button>
            </form>
        </div>
    </body>
    </html>
    """

@app.post("/upload/")
async def upload_file(
    file: UploadFile,
    background_tasks: BackgroundTasks,
    metadata: Optional[Dict[str, Any]] = None
):
    try:
        # Save uploaded file temporarily
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            content = await file.read()
            temp_file.write(content)
            temp_path = temp_file.name

        # Process with storage service    
        result = storage.upload_file(temp_path, metadata)
        
        # Cleanup in background
        background_tasks.add_task(os.unlink, temp_path)
        
        return JSONResponse(
            status_code=201,
            content=result
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/files/{file_id}")
async def get_file_info(file_id: str):
    info = storage.get_file_info(file_id)
    if not info:
        raise HTTPException(status_code=404, detail="File not found")
    return info

@app.get("/download/{file_id}")
async def download_file(file_id: str, background_tasks: BackgroundTasks):
    try:
        content = storage.download_file(file_id)
        file_info = storage.get_file_info(file_id)
        
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(content)
            temp_path = temp_file.name
            
        background_tasks.add_task(os.unlink, temp_path)
            
        return FileResponse(
            temp_path,
            media_type="application/octet-stream",
            filename=file_info['metadata']['original_name']
        )
        
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))
    
@app.get("/search/")
async def search_content(keyword: str, min_score: float = 0.1):
    try:
        results = storage.search_by_keyword(keyword, min_score)
        return JSONResponse(
            status_code=200,
            content={"results": results}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))    
    