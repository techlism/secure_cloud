from main import SecureFileUploader


    
if __name__ == "__main__":
    uploader = SecureFileUploader("http://15.206.89.160:8000")
    print(uploader.verify_blocks("5184be96-6594-4b3a-b92b-534517f20be4",["11242d9db02234904b75d43a622c6005645aa40758b13bd8e0e81d28c9cd5d0d"]))