from main import SecureFileUploader


    
if __name__ == "__main__":
    uploader = SecureFileUploader("http://15.206.89.160:8000")
    print(uploader.verify_blocks("187ebb27-c743-4a0d-9e91-2a647fa9d90b",["0"]))