from app import app

with app.test_client() as client:
    rv = client.get('/login')
    print('Status:', rv.status_code)
    print(rv.data.decode('utf-8')[:1200])
