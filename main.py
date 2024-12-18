import hashlib

def hash(text):
    # Hash the input text using SHA-256
    hashed = hashlib.sha256(text.encode('utf-8')).hexdigest()
    return hashed

text = input("Enter your text: ")
hashed_text = hash(text)
print("Hashed value:", hashed_text)