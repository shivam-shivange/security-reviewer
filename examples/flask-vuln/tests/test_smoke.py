from app import app

def test_home_ok():
    c = app.test_client()
    assert c.get("/user?name=alice").status_code == 200
