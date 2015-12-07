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
        # Encryption keys holds tuples called "keypairs" in the form
        #   ( private key hash , encrypted secret key )
        # We use a secure hash library that implements non-reversible hashes
        # so we are not in danger of revealing our secret keys
        self.encryption_keys = []

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
        import hashlib
        for user in allowed_users:
            pubkey = secfs.fs.usermap[user]
            private_key_hash = secfs.crypto.get_privhash(user)
            keypair = (private_key_hash, secfs.crypto.encrypt_asym(pubkey, symkey))
            self.encryption_keys.append(keypair)

    def get_key(self, user):
        if not isinstance(user, User):
            raise TypeError("{} cannot retrieve an encrypted key \
                because it is not a user".format(user))
        private_key = secfs.crypto.keys[user]
        # Get the RSA encrypted symmetric key particular to this user
        import hashlib
        for keypair in self.encryption_keys:
            priv_key_hash, encrypted_key = keypair
            # Check this user's private key hash against the other's
            my_priv_key_hash = secfs.crypto.get_privhash(user)
            if my_priv_key_hash == priv_key_hash:
                # Use private key decryption to retrieve original sym key
                return secfs.crypto.decrypt_asym(private_key, encrypted_key)
        raise Exception("(in get_key): User not found among private keys")

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
