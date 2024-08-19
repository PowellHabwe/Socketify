# test_ssl.py
import ssl

def test_ssl():
    print("SSL module is available")
    print("Available attributes and methods:")
    print(dir(ssl))
    try:
        context = ssl.create_default_context()
        print("SSL context created successfully")
    except Exception as e:
        print(f"Error creating SSL context: {e}")

if __name__ == "__main__":
    test_ssl()
