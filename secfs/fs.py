# This file implements file system operations at the level of inodes.

import time
import secfs.crypto
import secfs.tables
import secfs.access
import secfs.store.tree
import secfs.store.block
from secfs.store.inode import Inode
from secfs.store.tree import Directory
from cryptography.fernet import Fernet
from secfs.types import I, Principal, User, Group

# usermap contains a map from a User object to their public key according to /.users
usermap = {}
# groupmap contains a map from a Group object to the list of members according to /.groups
groupmap = {}
# owner is the user principal that owns the current share
owner = None
# root_i is the i of the root of the current share
root_i = None

def get_inode(i):
    """
    Shortcut for retrieving an inode given its i.
    """
    ihash = secfs.tables.resolve(i)
    if ihash == None:
        raise LookupError("asked to resolve i {}, but i does not exist".format(i))

    return Inode.load(ihash)

def init(owner, users, groups):
    """
    init will initialize a new share root as the given user principal. This
    includes setting up . and .. in the root directory, as well as adding the
    .users and .groups files that list trusted user public keys and group
    memberships respectively. This function will only allocate the share's
    root, but not map it to any particular share at the server. The new root's
    i is returned so that this can be done by the caller.
    """
    if not isinstance(owner, User):
        raise TypeError("{} is not a User, is a {}".format(owner, type(owner)))

    node = Inode()
    node.kind = 0
    node.ex = True
    node.owner = owner
    node.ctime = time.time()
    node.mtime = node.ctime

    ihash = secfs.store.block.store(node.bytes())
    root_i = secfs.tables.modmap(owner, I(owner), ihash)
    if root_i == None:
        raise RuntimeError

    new_ihash = secfs.store.tree.add(root_i, b'.', root_i)
    secfs.tables.modmap(owner, root_i, new_ihash)
    new_ihash = secfs.store.tree.add(root_i, b'..', root_i)
    secfs.tables.modmap(owner, root_i, new_ihash)
    print("CREATED ROOT AT", new_ihash)

    init = {
        b".users": users,
        b".groups": groups,
    }

    import pickle
    for fn, c in init.items():
        bts = pickle.dumps(c)

        node = Inode()
        node.kind = 1
        node.size = len(bts)
        node.mtime = node.ctime
        node.ctime = time.time()
        node.blocks = [secfs.store.block.store(bts)]

        ihash = secfs.store.block.store(node.bytes())
        i = secfs.tables.modmap(owner, I(owner), ihash)
        link(owner, i, root_i, fn)

    return root_i

def _create(parent_i, name, create_as, create_for, isdir, encrypt):
    """
    _create allocates a new file, and links it into the directory at parent_i
    with the given name. The new file is owned by create_for, but is created
    using the credentials of create_as. This distinction is necessary as a user
    principal is needed for the final i when creating a file as a group.
    """
    if not isinstance(parent_i, I):
        raise TypeError("{} is not an I, is a {}".format(parent_i, type(parent_i)))
    if not isinstance(create_as, User):
        raise TypeError("{} is not a User, is a {}".format(create_as, type(create_as)))
    if not isinstance(create_for, Principal):
        raise TypeError("{} is not a Principal, is a {}".format(create_for, type(create_for)))

    assert create_as.is_user() # only users can create
    assert create_as == create_for or create_for.is_group() # create for yourself or for a group

    if create_for.is_group() and create_for not in groupmap:
        raise PermissionError("cannot create for unknown group {}".format(create_for))

    # This check is performed by link() below, but better to fail fast
    if not secfs.access.can_write(create_as, parent_i):
        if parent_i.p.is_group():
            raise PermissionError("cannot create in group-writeable directory {0} as {1}; user is not in group".format(parent_i, create_as))
        else:
            raise PermissionError("cannot create in user-writeable directory {0} as {1}".format(parent_i, create_as))

    node = Inode()
    node.ctime = time.time()
    node.mtime = node.ctime
    node.kind = 0 if isdir else 1
    node.ex = isdir

    # Encrypt if needed
    sym_key = None
    if encrypt:
        symkey = Fernet.generate_key()
        node.encrypt(create_for, symkey)

    # Here, you will need to:
    #
    #  - [DONE] store the newly created inode (node.bytes()) on the server
    #  - [DONE] map that block to an i owned by the user
    #  - [DONE] if a directory is being created, create entries for . and ..
    #  - [DONE] if create_for is a group, you will
    #    also have to create a group i for that group, and point it to the user's i
    #  - [DONE] call link() to link the new i into the directory at parent_i with the
    #    given name
    #
    # Also make sure that you *return the final i* for the new inode!

    new_ihash = secfs.store.block.store(node.bytes())
    new_i = secfs.tables.modmap(create_as, I(create_for), new_ihash)

    if isdir:
      # link calls tree.add and modmap within
      link(create_as, new_i, new_i, b'.')
      link(create_as, parent_i, new_i, b'..')

    # Finally link this directory to the parent
    link(create_as, new_i, parent_i, name)
    return new_i

def create(parent_i, name, create_as, create_for, encrypt):
    """
    Create a new file.
    See secfs.fs._create
    """
    return _create(parent_i, name, create_as, create_for, False, encrypt)

def mkdir(parent_i, name, create_as, create_for, encrypt):
    """
    Create a new directory.
    See secfs.fs._create
    """
    print("Current ITables: {}".format(secfs.tables.current_itables))
    return _create(parent_i, name, create_as, create_for, True, encrypt)

def read(read_as, i, off, size):
    """
    Read reads [off:off+size] bytes from the file at i.
    """
    if not isinstance(i, I):
        raise TypeError("{} is not an I, is a {}".format(i, type(i)))
    if not isinstance(read_as, User):
        raise TypeError("{} is not a User, is a {}".format(read_as, type(read_as)))

    print("->[INFO]: User {} trying to read {}".format(read_as, i))
    if not secfs.access.can_read(read_as, i):
        if i.p.is_group():
            raise PermissionError("cannot read from group-readable file {0} as {1}; user is not in group".format(i, read_as))
        else:
            raise PermissionError("cannot read from user-readable file {0} as {1}".format(i, read_as))

    # Inode.read() deciphers blocks if necessary 
    return get_inode(i).read(read_as)[off:off+size]

def write(write_as, i, off, buf):
    """
    Write writes the given bytes into the file at i at the given offset.
    """
    if not isinstance(i, I):
        raise TypeError("{} is not an I, is a {}".format(i, type(i)))
    if not isinstance(write_as, User):
        raise TypeError("{} is not a User, is a {}".format(write_as, type(write_as)))

    if not secfs.access.can_write(write_as, i):
        if i.p.is_group():
            raise PermissionError("cannot write to group-owned file {0} as {1}; user is not in group".format(i, write_as))
        else:
            raise PermissionError("cannot write to user-owned file {0} as {1}".format(i, write_as))

    node = get_inode(i)

    # TODO: this is obviously stupid -- should not get rid of blocks that haven't changed
    bts = node.read(write_as)

    # write also allows us to extend a file
    if off + len(buf) > len(bts):
        bts = bts[:off] + buf
    else:
        bts = bts[:off] + buf + bts[off+len(buf):]

    # update the inode
    node.write(write_as, bts)
    # node.blocks = [secfs.store.block.store(bts)] <- originally
    node.mtime = time.time()
    node.size = len(bts)

    # put new hash in tree
    new_hash = secfs.store.block.store(node.bytes())
    secfs.tables.modmap(write_as, i, new_hash)

    return len(buf)

def readdir(i, off):
    """
    Return a list of is in the directory at i.
    Each returned list item is a tuple of an i and an index. The index can be
    used to request a suffix of the list at a later time.
    """
    dr = Directory(i)
    if dr == None:
        return None

    return [(i, index+1) for index, i in enumerate(dr.children) if index >= off]

def link(link_as, i, parent_i, name):
    """
    Adds the given i into the given parent directory under the given name.
    """
    if not isinstance(parent_i, I):
        raise TypeError("{} is not an I, is a {}".format(parent_i, type(parent_i)))
    if not isinstance(i, I):
        raise TypeError("{} is not an I, is a {}".format(i, type(i)))
    if not isinstance(link_as, User):
        raise TypeError("{} is not a User, is a {}".format(link_as, type(link_as)))
    if not secfs.access.can_write(link_as, parent_i):
        if parent_i.p.is_group():
            raise PermissionError("cannot create in group-writeable directory {0} as {1}; user is not in group".format(parent_i, link_as))
        else:
            raise PermissionError("cannot create in user-writeable directory {0} as {1}".format(parent_i, link_as))

    parent_ihash = secfs.store.tree.add(parent_i, name, i)
    secfs.tables.modmap(link_as, parent_i, parent_ihash)

def unlink(unlink_as, parent_i, name):
    i = secfs.store.tree.find_under(parent_i, name)
    if i == None:
        # TODO: "No such file or directory" error?
        return
    if not isinstance(parent_i, I):
        raise TypeError("{} is not an I, is a {}".format(parent_i, type(parent_i)))
    if not isinstance(i, I):
        raise TypeError("{} is not an I, is a {}".format(i, type(i)))
    if not isinstance(unlink_as, User):
        raise TypeError("{} is not a User, is a {}".format(unlink_as, type(unlink_as)))

    # Check parent directory perms
    if not secfs.access.can_write(unlink_as, parent_i):
        if parent_i.p.is_group():
            raise PermissionError("cannot unlink from parent directory {0} as {1}; user is not in group".format(parent_i, unlink_as))
        else:
            raise PermissionError("cannot unlink from parent directory {0} as {1}".format(parent_i, unlink_as))
    # Check child directory/file perms
    if not secfs.access.can_write(unlink_as, i):
        if i.p.is_group():
            raise PermissionError("cannot unlink {0} as {1}; user is not in group".format(i, unlink_as))
        else:
            raise PermissionError("cannot unlink {0} as {1}".format(i, unlink_as))

    # Remove from parent directory
    new_ihash = secfs.store.tree.remove(parent_i, name)
    secfs.tables.modmap(unlink_as, parent_i, new_ihash)
    # Remove all references to the file in itables
    secfs.tables.modunmap(unlink_as, i)
