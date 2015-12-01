# This file contains all code handling the resolution and modification of i
# mappings. This includes group handle indirection and VSL validation, so the
# file is somewhat hairy.
# NOTE: an ihandle is the hash of a principal's itable, which holds that
# principal's mapping from inumbers (the second part of an i) to inode hashes.

import pickle
import secfs.crypto
import secfs.fs
import secfs.store
from secfs.types import I, Principal, User, Group

# TODO: The version structure list is just a list of tuples in the form:
#   - (uid, i-handle, group-list, version-vector, signature)
#       - the "group-list" is a map from gid's to ihandles
#       - the "version-vector" is a map from uid/gid's to versions
current_vsl = []
# current_itables represents the current view of the file system's itables
current_itables = {}

# a server connection handle is passed to us at mount time by secfs-fuse
server = None
def register(_server):
    global server
    server = _server

def validate_vsl(new_vsl):
    global current_vsl

    # Step 1: Ensure fork-consistency by making sure
    # the previous VSL is a prefix of the new one
    for i, vs in enumerate(current_vsl):
        if new_vsl[i] != vs:
            # Prefixes don't match, the last change from this client was not
            # properly registered
            return False

    # Step 2: Ensure that valid users have made changes
    # to the VSL by checking signatures on new changes
    for i in range(len(current_vsl), len(new_vsl)):
        # TODO(Conner): Signature verification using crypto.py
        (uid, _, _, _, sig) = new_vsl
        # Do we have the public key
        if uid not in usermap:
          return False
        key =  usermap[uid]
        # Verify signature
        if not crypto.verify(sig, key, repr(new_vsl)):
            return False
        
    # Passed all tests
    return True

def upload_vsl():
    global server, current_vsl
    serialized_vsl = pickle.dumps(current_vsl)
    server.upload_vsl(serialized_vsl)

def download_vsl():
    '''
    Downloads and validates the VSL.
    Updates global data structures.

    returns: True on successful validation, False otherwise
    '''
    global server
    vsl_blob = server.download_vsl()

    # the RPC layer will base64 encode binary data
    import base64
    serialized_vsl = base64.b64decode(vsl_blob)

    # Populate global VSL
    new_vsl = pickle.loads(serialized_vsl)

    # Validate
    if not validate_vsl(new_vsl):
        return False

    global current_vsl
    current_vsl = new_vsl
    return True

def populate_itables():
    global current_vsl
    ghandle_mappings = {}
    # Use the user's i-handle to populate the relevant i-tables
    for vs in current_vsl:
        uid, ihandle, ghandle_map, vvector, sig = vs
        current_itables[User(uid)] = retrieve_itable(ihandle)

    # Now do the same for the group i-handles


def pre(refresh, user):
    """
    Called before all user file system operations, right after we have obtained
    an exclusive server lock.
    """

    if refresh != None:
        # refresh usermap and groupmap
        refresh()

    # Pull the VSL and initialize I-Tables
    download_vsl()
    populate_itables()

def post(push_vs):
    if not push_vs:
        # when creating a root, we should not push a VS (yet)
        # you will probably want to leave this here and
        # put your post() code instead of "pass" below.
        return
    # Store the VSL


class Itable:
    """
    An itable holds a particular principal's mappings from inumber (the second
    element in an i tuple) to an inode hash for users, and to a user's i for
    groups.
    """
    def __init__(self):
        self.mapping = {}

    def load(ihandle):
        b = secfs.store.block.load(ihandle)
        if b == None:
            return None

        t = Itable()
        t.mapping = pickle.loads(b)
        return t

    def bytes(self):
        return pickle.dumps(self.mapping)

def resolve(i, resolve_groups = True):
    """
    Resolve the given i into an inode hash. If resolve_groups is not set, group
    i's will only be resolved to their user i, but not further.

    In particular, for some i = (principal, inumber), we first find the itable
    for the principal, and then find the inumber-th element of that table. If
    the principal was a user, we return the value of that element. If not, we
    have a group i, which we resolve again to get the ihash set by the last
    user to write the group i.
    """
    if not isinstance(i, I):
        raise TypeError("{} is not an I, is a {}".format(i, type(i)))

    principal = i.p

    if not isinstance(principal, Principal):
        raise TypeError("{} is not a Principal, is a {}".format(principal, type(principal)))

    if not i.allocated():
        # someone is trying to look up an i that has not yet been allocated
        return None

    global current_itables
    if principal not in current_itables:
        # User does not yet have an itable
        return None 

    t = current_itables[principal]

    if i.n not in t.mapping:
        raise LookupError("principal {} does not have i {}".format(principal, i))

    # santity checks
    if principal.is_group() and not isinstance(t.mapping[i.n], I):
        raise TypeError("looking up group i, but did not get indirection ihash")
    if principal.is_user() and isinstance(t.mapping[i.n], I):
        raise TypeError("looking up user i, but got indirection ihash")

    if isinstance(t.mapping[i.n], I) and resolve_groups:
        # we're looking up a group i
        # follow the indirection
        return resolve(t.mapping[i.n])

    return t.mapping[i.n]

def modmap(mod_as, i, ihash):
    """
    Changes or allocates i so it points to ihash.

    If i.allocated() is false (i.e. the I was created without an i-number), a
    new i-number will be allocated for the principal i.p. This function is
    complicated by the fact that i might be a group i, in which case we need
    to:

      1. Allocate an i as mod_as
      2. Allocate/change the group i to point to the new i above

    modmap returns the mapped i, with i.n filled in if the passed i was no
    allocated.
    """
    if not isinstance(i, I):
        raise TypeError("{} is not an I, is a {}".format(i, type(i)))
    if not isinstance(mod_as, User):
        raise TypeError("{} is not a User, is a {}".format(mod_as, type(mod_as)))

    assert mod_as.is_user() # only real users can mod

    # Group i-table modification
    if mod_as != i.p:
        print("trying to mod object for {} through {}".format(i.p, mod_as))
        assert i.p.is_group() # if not for self, then must be for group

        real_i = resolve(i, False)
        if isinstance(real_i, I) and real_i.p == mod_as:
            # We updated the file most recently, so we can just update our i.
            # No need to change the group i at all.
            # This is an optimization.
            i = real_i
        elif isinstance(real_i, I) or real_i == None:
            if isinstance(ihash, I):
                # Caller has done the work for us, so we just need to link up
                # the group entry.
                print("mapping", i, "to", ihash, "which again points to", resolve(ihash))
            else:
                # Allocate a new entry for mod_as, and continue as though ihash
                # was that new i.
                # XXX: kind of unnecessary to send two VS for this
                _ihash = ihash
                ihash = modmap(mod_as, I(mod_as), ihash)
                print("mapping", i, "to", ihash, "which again points to", _ihash)
        else:
            # This is not a group i!
            # User is trying to overwrite something they don't own!
            raise PermissionError("illegal modmap; tried to mod i {0} as {1}".format(i, mod_as))

    # find (or create) the principal's itable
    t = None
    global current_itables
    if i.p not in current_itables:
        if i.allocated():
            # this was unexpected;
            # user did not have an itable, but an inumber was given
            raise ReferenceError("itable not available")
        t = Itable()
        print("no current list for principal", i.p, "; creating empty table", t.mapping)
    else:
        t = current_itables[i.p]

    # look up (or allocate) the inumber for the i we want to modify
    if not i.allocated():
        inumber = 0
        while inumber in t.mapping:
            inumber += 1
        i.allocate(inumber)
    else:
        if i.n not in t.mapping:
            raise IndexError("invalid inumber")

    # modify the entry, and store back the updated itable
    if i.p.is_group():
        print("mapping", i.n, "for group", i.p, "into", t.mapping)
    t.mapping[i.n] = ihash # for groups, ihash is an i
    current_itables[i.p] = t
    return i
