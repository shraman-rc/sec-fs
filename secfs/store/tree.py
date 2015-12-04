# This file provides functionality for manipulating directories in SecFS.

import pickle
import secfs.fs
import secfs.crypto
import secfs.tables
import secfs.store.block
from secfs.store.inode import Inode
from secfs.types import I, Principal, User, Group

def find_under(dir_i, name):
    """
    Attempts to find the i of the file or directory with the given name under
    the directory at i.
    """
    if not isinstance(dir_i, I):
        raise TypeError("{} is not an I, is a {}".format(dir_i, type(dir_i)))

    dr = Directory(dir_i)
    for f in dr.children:
        if f[0] == name:
            return f[1]
    return None

class Directory:
    """
    A Directory is used to marshal and unmarshal the contents of directory
    inodes. To load a directory, an i must be given.
    """
    def __init__(self, i):
        if not isinstance(i, I):
            raise TypeError("{} is not an I, is a {}".format(i, type(i)))

        self.inode = None
        self.children = []

        self.inode = secfs.fs.get_inode(i)
        if self.inode.kind != 0:
            raise TypeError("inode with ihash {} is not a directory".format(ihash))

        # If group, go down one level of indirection to retrieve the user
        # (required for decryption purposes)
        self.user_owner = i.p
        if self.user_owner.is_group():
            self.user_owner = secfs.tables.resolve(i, False)

        cnt = self.inode.read(self.user_owner)
        if len(cnt) != 0:
            self.children = pickle.loads(cnt)

    def bytes(self):
        return pickle.dumps(self.children)

def add(dir_i, name, i):
    """
    Updates the directory's inode contents to include an entry for i under the
    given name.
    """
    if not isinstance(dir_i, I):
        raise TypeError("{} is not an I, is a {}".format(dir_i, type(dir_i)))
    if not isinstance(i, I):
        raise TypeError("{} is not an I, is a {}".format(i, type(i)))

    dr = Directory(dir_i)
    for f in dr.children:
        if f[0] == name:
            raise KeyError("asked to add i {} to dir {} under name {}, but name already exists".format(i, dir_i, name))

    dr.children.append((name, i))
    # Don't call secfs.store.block directly, use inode builtins for encryption
    dr.inode.write(dr.user_owner, dr.bytes())
    #new_dhash = secfs.store.block.store(dr.bytes(), sym_key)
    #dr.inode.blocks = [new_dhash]
    new_ihash = secfs.store.block.store(dr.inode.bytes())
    return new_ihash
