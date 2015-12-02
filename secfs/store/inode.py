import pickle
import secfs.store.block
import secfs.crypto

class Inode:
    def __init__(self):
        self.size = 0
        self.kind = 0        # 0 is dir, 1 is file
        self.ex = False
        self.uwrite = True   # User write
        self.enc = False     # World readable
        self.ctime = 0
        self.mtime = 0
        self.key = None
        self.blocks = []

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

    def read(self):
        """
        Reads the block content of this inode.
        """
        return b"".join([secfs.store.block.load(b) for b in self.blocks])

    def bytes(self):
        """
        Serialize this inode and return the corresponding bytestring.
        """
        b = self.__dict__
        return pickle.dumps(b)
