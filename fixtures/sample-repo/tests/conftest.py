import hashlib

# Test scaffolding. Should never appear on a worklist.
def fixture_digest(data):
    return hashlib.sha1(data).hexdigest()
