import secfs.fs
from secfs.types import I, Principal, User, Group

def is_encrypted(i):
    """
    Determine if the file pointed to by the given I
    is encrypted
    """
    inode = secfs.fs.get_inode(i)
    return inode.encrypted

def can_read(user, i):
    """
    Returns True if the given user can read the given i.
    """
    if not isinstance(user, User):
        raise TypeError("{} is not a User, is a {}".format(user, type(user)))

    if not isinstance(i, I):
        raise TypeError("{} is not an I, is a {}".format(i, type(i)))

    # If I is encrypted, it undergoes same permission checks as 'write'
    if is_encrypted(i):
        print("->[INFO]: User {} trying to access encrypted file {}".format(user, i))
        # If i is owned by a user, and that user isn't you, you can't read
        if i.p.is_user() and i.p != user:
            return False

        # If a group owns i, and you aren't in the group, you can't read
        if i.p.is_group() and (i.p not in secfs.fs.groupmap or user not in secfs.fs.groupmap[i.p]):
            return False

    return True

def can_write(user, i):
    """
    Returns True if the given user can modify the given i.
    """
    if not isinstance(user, User):
        raise TypeError("{} is not a User, is a {}".format(user, type(user)))

    if not isinstance(i, I):
        raise TypeError("{} is not an I, is a {}".format(i, type(i)))

    # If i is owned by a user, and that user isn't you, you can't write
    if i.p.is_user() and i.p != user:
        return False

    # If a group owns i, and you aren't in the group, you can't write
    if i.p.is_group() and (i.p not in secfs.fs.groupmap or user not in secfs.fs.groupmap[i.p]):
        return False

    return True

def can_execute(user, i):
    """
    Returns True if the given user can execute the given i.
    """
    if not isinstance(user, User):
        raise TypeError("{} is not a User, is a {}".format(user, type(user)))

    if not secfs.access.can_read(user, i):
        return False

    # check x bits
    node = secfs.fs.get_inode(i)
    return node.ex
