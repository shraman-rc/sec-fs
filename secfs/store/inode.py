import pickle
import secfs.store.block
import secfs.crypto
import secfs.fs
from secfs.types import I, Principal, User, Group

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
        print("->[INFO]: Encrypting inode as {}".format(p))
        self.encrypted = True
        allowed_users = []

        # If group, then we should have several different encrypted
        # versions of the symmetric key for each user
        if p.is_group():
            allowed_users = secfs.fs.groupmap[p]
        else:
            allowed_users = [p]

        # Perform PKE on per-user basis to avoid group indirection
        print("->[INFO]: Allowed users: {}".format(allowed_users))
        for user in allowed_users:
            pubkey = secfs.fs.usermap[user]
            self.encryption_keys[user.id] = secfs.crypto.encrypt_asym(pubkey, symkey)

    def rotate_key(self, user, new_key):
        sym_key = self.get_key(user) 
        self.encryption_keys[user.id] = secfs.crypto.encrypt_asym(new_key, sym_key)

    def get_key(self, user):
        if not isinstance(user, User):
            raise TypeError("{} cannot retrieve an encrypted key \
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

    def read(self, read_as=None):
        """
        Reads the block content of this inode.
        """
        blocks = [secfs.store.block.load(b) for b in self.blocks]
        if self.encrypted:
            print("->[INFO]: Decrypting as {}".format(read_as))
            if read_as == None:
                raise Exception("read_as must be declared param for encrypted inodes")
            # Otherwise, decrypt the blocks
            sym_key = self.get_key(read_as)
            blocks = [secfs.store.block.load(b, sym_key) for b in self.blocks]
        return b"".join(blocks)

    def write(self, write_as, bts):
        sym_key = None
        if self.encrypted:
            # Encrypt the data using sym_key
            sym_key = self.get_key(write_as)
        self.blocks = [secfs.store.block.store(bts, sym_key)]

    def bytes(self):
        """
        Serialize this inode and return the corresponding bytestring.
        """
        b = self.__dict__
        return pickle.dumps(b)
