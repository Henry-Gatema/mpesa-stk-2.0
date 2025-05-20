import secrets
import base64

# Generate a secure random key
def generate_key():
    return base64.b64encode(secrets.token_bytes(32)).decode('utf-8')

if __name__ == '__main__':
    secret_key = generate_key()
    jwt_secret_key = generate_key()
    
    print("\n=== Secure Keys Generated ===")
    print("\nSECRET_KEY:")
    print(secret_key)
    print("\nJWT_SECRET_KEY:")
    print(jwt_secret_key)
    print("\n=== Copy these keys to your Render environment variables ===") 