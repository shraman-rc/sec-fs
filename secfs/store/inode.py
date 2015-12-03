import pickle
import secfs.store.block
import secfs.crypto
import secfs.fs

class Inode:
    def __init__(self):
        self.size = 0
        self.kind = 0 # 0 is dir, 1 is file
        self.ex = False
        self.ctime = 0
        self.mtime = 0
        self.blocks = []
        self.encrypted = False
        # Maps *uid* (not User objects) to ciphered sym key
        self.encryption_keys = {}

    def encrypt(self, p, symkey):
        self.encrypted = True
        allowed_users = []

        # If group, then we should have several different encrypted
        # versions of the symmetric key for each user
        if p.is_group():
            allowed_users = secfs.fs.groupmap[p]
        else:
            allowed_users = [p]

        # Perform PKE on per-user basis to avoid group indirection
        for user in allowed_users:
            pubkey = secfs.fs.usermap[user]
            self.encryption_keys[user.id] = secfs.crypto.encrypt_asym(pubkey, symkey)

    def get_key(self, user):
        if not isinstance(user, User):
            raise TypeError("{} cannot retrieve an encrypted key
                because it is not a user".format(user))
        # Get the RSA encrypted symmetric key particular to this user
        encrypted_key = self.encryption_keys[user.id]
        # Use private key decryption to retrieve original sym key
        private_key = secfs.crypto.keys[user]
        return secfs.crypto.decrypt_asym(private_key, encrypted_key) 

    def load(ihash):
        """
        Loads all meta information about an inode given its ihash.
        """
        d = secfs.store.block.load(ihash)
        if d == None:
            return None

        n = Inode()
        n.__dict__.update(pickle.loads(d))
        return n

    def read(self, read_as):
        """
        Reads the block content of this inode.
        """
        if not self.encrypted:
            return b"".join([secfs.store.block.load(b) for b in self.blocks])
        # Otherwise, decrypt the blocks
        sym_key = self.get_key(read_as)
        [secfs.store.block.load(b) for b in self.blocks]

    def bytes(self):
        """
        Serialize this inode and return the corresponding bytestring.
        """
        b = self.__dict__
        return pickle.dumps(b)
