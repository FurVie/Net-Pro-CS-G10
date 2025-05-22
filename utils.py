import hashlib

def calculate_checksum(data):
    """Return the checksum of the data"""
    return hashlib.sha256(data).hexdigest()
