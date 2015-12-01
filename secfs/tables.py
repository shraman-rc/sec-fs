# This file contains all code handling the resolution and modification of i
# mappings. This includes group handle indirection and VSL validation, so the
# file is somewhat hairy.
# NOTE: an ihandle is the hash of a principal's itable, which holds that
# principal's mapping from inumbers (the second part of an i) to inode hashes.

import pickle
import secfs.store
import secfs.fs
import pdb
from secfs.types import I, Principal, User, Group

# The version structure list is just a list of tuples in the form:
#   - (uid, i-handle, group-list, version-vector, signature)
#       - the "group-list" is a map from gid's to ihandles
#       - the "version-vector" is a map from uid/gid's to versions
current_vsl = []
old_vsl_length = 0
# current_itables represents the current snapshot of the file system
#   - maps Principal instances -> itables
current_itables = {}
old_itables = {}

# TODO: Remove
f = open("custom_output.out", "w")

# a server connection handle is passed to us at mount time by secfs-fuse
server = None
def register(_server):
    global server
    server = _server

def validate_vsl(new_vsl):
    '''
    returns: True if the new VSL is consistent, False otherwise
    '''
    global current_vsl

    if len(current_vsl) == 0:
        return True

    # Step 1: Ensure fork-consistency by making sure
    # the previous VSL is a prefix of the new one
    for i, vs in enumerate(current_vsl):
        if new_vsl[i] != vs:
            # Prefixes don't match, the last change from this client was not
            # properly registered
            return False

    # Step 2: Validate new changes:
    #   - Make sure they are totally ordered
    #   - Verify the signatures
    #   - Verify that the users had permission to sign those changes
    prev_vv = current_vsl[-1][3]
    for i in range(len(current_vsl), len(new_vsl)):
        # Sorted order check
        new_vv = new_vsl[i][3]
        for ugid in prev_vv:
            if prev_vv[ugid] > new_vv[ugid]:
                return False
        # TODO(Conner): Signature verification using crypto.py
        pass

    # Step 3: Check integrity of data blocks in the users itable?

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
    if "data" in vsl_blob:
        import base64
        serialized_vsl = base64.b64decode(vsl_blob["data"])
    else:
        raise Exception("failed to download vsl: no 'data' attribute in RPC blob")

    # Validate the newly downloaded VSL
    new_vsl = pickle.loads(serialized_vsl)
    if not validate_vsl(new_vsl):
        return False

    # Populate the global VSL with updated info
    global current_vsl, old_vsl_length
    old_vsl_length = len(current_vsl)
    current_vsl = new_vsl
    return True

def update_itables():
    global current_vsl, old_vsl_length, current_itables, old_itables
    new_user_ihandles = {}
    new_group_ihandles = {}

    # Iterate only through the new VS's
    for vs in current_vsl[old_vsl_length:]:
        uid, ihandle, gihandle_map, vvector, sig = vs
        new_user_ihandles[uid] = ihandle
        new_group_ihandles.update(gihandle_map)

    # Save a copy of the itables so we know which updates we should push to the server
    old_itables = dict(current_itables)

    # Now update the global itable reference to be used
    for uid in new_user_ihandles:
        current_itables[User(uid)] = Itable.load(new_user_ihandles[uid])
    for gid in new_group_ihandles:
        current_itables[Group(gid)] = Itable.load(new_group_ihandles[gid])

def pre(refresh, user):
    """
    Called before all user file system operations, right after we have obtained
    an exclusive server lock.
    """

    f.write("User {} acquiring lock.\n".format(user))

    if refresh != None:
        # refresh usermap and groupmap
        refresh()

    # Pull the VSL and initialize I-Tables
    if download_vsl():
        update_itables()
    else: # Failed validation TODO: How to handle this?
        raise Exception("Failed validation")

def post(push_vs, user):
    if not push_vs:
        # when creating a root, we should not push a VS (yet)
        # you will probably want to leave this here and
        # put your post() code instead of "pass" below.
        return

    global current_vsl, current_itables, old_itables
    # Gather which group itables have been updated
    new_gitables_map = {}
    for p in current_itables:
        if p.is_group() and (old_itables.get(p) == None or old_itables[p] != current_itables[p]):
            new_gitables_map[p.id] = current_itables[p]

    # Get the latest version vector
    new_vvector = {} if (len(current_vsl) == 0) else dict(current_vsl[-1][3])
    # Update user version
    new_vvector[user.id] = new_vvector.get(user.id, 0) + 1
    # Store user's itable and upload if it doesnt exist
    new_ihandle = secfs.store.block.store(current_itables.get(user, Itable()).bytes())
    # Do the same updates for groups
    new_gihandles_map = {}
    for gid in new_gitables_map:
        # Update the group version
        new_vvector[gid] = new_vvector.get(gid, 0) + 1
        # Store the new itable and save the hash
        itable = new_gitables_map[gid]
        new_gihandles_map[gid] = secfs.store.block.store(itable.bytes())

    # Create the new VS and update on the server
    signature = None # TODO: Conner?
    new_vs = (user.id, new_ihandle, new_gihandles_map, new_vvector, signature)
    current_vsl.append(new_vs)
    upload_vsl()

    # Reset the current user after operation complete
    f.write("User {} about to release lock.\n".format(user))


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
