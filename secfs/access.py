import secfs.fs
from secfs.types import I, Principal, User, Group

def can_read(user, i):
    """
    Returns True if the given user can read the given i.
    """
    if not isinstance(user, User):
        raise TypeError("{} is not a User, is a {}".format(user, type(user)))

    if not isinstance(i, I):
        raise TypeError("{} is not an I, is a {}".format(i, type(i)))

    # If i is owned by a user, and that user is you, you can write if permitted
    if i.p.is_user() and i.p == user:
      print("Is user, reading")
      return True

    # If a group owns i, and you are in the group, you can read
    if i.p.is_group() and (i.p in secfs.fs.groupmap or user in secfs.fs.groupmap[i.p]):
        print("Is group, reading")
        return True

    # Otherwise can only read if not encrypted
    node = secfs.fs.get_inode(i)

    print("Is world, reading:", not node.enc)
    return not node.enc

def can_write(user, i):
    """
    Returns True if the given user can modify the given i.
    """
    print("User:", str(user))
    print("I:", str(i))
    print("Groupmap:", str(secfs.fs.groupmap))
    print("Usermap:", str(secfs.fs.usermap))
    if not isinstance(user, User):
        raise TypeError("{} is not a User, is a {}".format(user, type(user)))

    if not isinstance(i, I):
        raise TypeError("{} is not an I, is a {}".format(i, type(i)))

    # If i is owned by a user, and that user is you, you can write if privileged
    print("is user:", i.p.is_user())
    print("is user:", i.p == user)
    if i.p.is_user() and i.p == user:
        node = secfs.fs.get_inode(i)
        print("Is user, reading:", node.uwrite)
        if node.uwrite:
          return True

    print("Is group:", i.p.is_group())
    print("Is in group map:", i.p in secfs.fs.groupmap)

    # If a group owns i, and you are in the group, you can write
    if i.p.is_group() and (i.p in secfs.fs.groupmap or user in secfs.fs.groupmap[i.p]):
        print("Is group, writing")
        return True

    
    print("Is world, not writing")
    return False

def can_execute(user, i):
    """
    Returns True if the given user can execute the given i.
    """
    #check x bits
    node = secfs.fs.get_inode(i)

    print("Is executing:", node.ex)
    return node.ex
