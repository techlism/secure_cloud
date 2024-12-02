from main import SecureFileUploader


    
if __name__ == "__main__":
    uploader = SecureFileUploader("http://15.206.89.160:8000")
    print(uploader.verify_blocks("8a96b0d2-e67d-4ada-ad0c-325d00b0b9e3",["11242d9db02234904b75d43a622c6005645aa40758b13bd8e0e81d28c9cd5d0d"]))