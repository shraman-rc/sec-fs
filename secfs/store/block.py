# This file handles all interaction with the SecFS server's blob storage.
import secfs.crypto

# a server connection handle is passed to us at mount time by secfs-fuse
server = None
def register(_server):
    global server
    server = _server

def store(blob, sym_key=None):
    """
    Store the given blob at the server, and return the content's hash.
    """
    global server
    # Encrypt if requested
    if sym_key != None:
        blob = secfs.crypto.encrypt_sym(sym_key, blob)
    return server.store(blob)

def load(chash, sym_key=None):
    """
    Load the blob with the given content hash from the server.
    """
    global server
    blob = server.read(chash)

    # the RPC layer will base64 encode binary data
    if "data" in blob:
        import base64
        blob = base64.b64decode(blob["data"])

    # Decrypt if requested
    if sym_key != None:
        blob = secfs.crypto.decrypt_sym(sym_key, blob)

    return blob

def remove(chashes):
    global server
    for chash in chashes:
        server.remove(chash)
