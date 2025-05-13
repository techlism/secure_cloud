## Running the Server

1. **Start the FastAPI server**:
   ```
   uvicorn main:app --host 0.0.0.0 --port 8000
   ```

## Using the Client

### Basic Commands

1. **Upload a file**:
   ```
   python main.py upload /path/to/your/file.txt
   ```
   
   With custom keywords:
   ```
   python main.py upload /path/to/your/file.txt --keywords keyword1 keyword2
   ```

2. **List all files**:
   ```
   python main.py list
   ```

3. **Search files by keywords**:
   ```
   python main.py search keyword1 keyword2
   ```

4. **Get file information**:
   ```
   python main.py info <file-id>
   ```

5. **Download a file**:
   ```
   python main.py download <file-id>
   ```
   
   To a specific location:
   ```
   python main.py download <file-id> --output /path/to/save
   ```

### Advanced Features

1. **Verify file integrity (PoR)**:
   ```
   python main.py por <file-id>
   ```
   
   Multiple files:
   ```
   python main.py por <file-id-1> <file-id-2>
   ```

2. **Audit specific blocks across multiple files**:
   ```
   python main.py audit "file-id-1 file-id-2 0,1,3"
   ```
   
   This audits blocks 0, 1, and 3 of both file-id-1 and file-id-2.

3. **Verbose logging**:
   ```
   python main.py -v <command>
   ```

4. **Use custom server**:
   ```
   python main.py --server http://custom-server:8000 <command>
   ```

## Command Reference

```
usage: main.py [-h] [--server SERVER] [--verbose] {upload,audit,por,list,search,info,download} ...

Secure File Client with Shacham-Waters PoR

optional arguments:
  -h, --help            show this help message and exit
  --server SERVER       Server URL
  --verbose, -v         Enable verbose logging

commands:
  {upload,audit,por,list,search,info,download}
    upload              Upload a file
    audit               Audit specific files and blocks
    por                 Request PoR proof for multiple files
    list                List all files stored on the server
    search              Search for files by keywords
    info                Get detailed information about a file
    download            Download a file from the server
```