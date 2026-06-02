from tickettool.hello import greet


def test_greet():
    assert greet("world") == "hello, world!"
