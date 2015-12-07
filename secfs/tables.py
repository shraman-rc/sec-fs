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

# The version structure list is just a list of tuples in the form:
#   - (uid, i-handle, group-list, version-vector, signature)
#       - the "group-list" is a map from gid's to ihandles
#       - the "version-vector" is a map from uid/gid's to versions
#       - the "signature" the signed vsl
current_vsl = []
# current_itables represents the current snapshot of the file system
#   - maps Principal instances -> itables
current_itables = {}
# For garbage collection
garbage_ihashes = set()

# a server connection handle is passed to us at mount time by secfs-fuse
server = None
def register(_server):
    global server
    server = _server

def print_vs(vs):
    return "VS {}\n\t\tihandle={}\n\t\tghandles={}\n\t\tversion-vector={}".format(*vs[:-1])

def get_groups(user):
    groups = []
    for group in secfs.fs.groupmap:
        if user in secfs.fs.groupmap[group]:
            groups.append(group)
    return groups

def upload_vsl():
    print("->[INFO]: Uploading VSL:\n\t{}".format( "\n\t".join([print_vs(vs) for vs in current_vsl]) ))
    global server, current_vsl
    serialized_vsl = pickle.dumps(current_vsl)
    server.upload_vsl(serialized_vsl)

def download_vsl(only_check_root=False):
    '''
    Downloads and validates the VSL.
    Updates global data structures including itables.

    returns: True on successful validation and updating, False otherwise
    '''
    print("->[INFO]: Downloading VSL. Only check root={}".format(only_check_root))
    global server
    vsl_blob = server.download_vsl()

    # the RPC layer will base64 encode binary data
    if "data" in vsl_blob:
        import base64
        serialized_vsl = base64.b64decode(vsl_blob["data"])
    else:
        #f.write("[ERROR]: Failed to download VSL: no 'data' attribute in blob.\n")
        print("->[ERROR]: Failed to download VSL: no 'data' attribute in blob.")
        raise Exception("failed to download vsl: no 'data' attribute in RPC blob")

    # Deserialize VSL
    global current_vsl
    current_vsl = pickle.loads(serialized_vsl)
    print("->[INFO]: Downloaded VSL:\n\t{}".format( "\n\t".join([print_vs(vs) for vs in current_vsl])))

    # --- Validation --- #
    #   1. Make sure they are totally ordered
    if len(current_vsl) > 1:
        prev_vv = current_vsl[0][3]
        for vs in current_vsl[1:]:
            (uid, ihandle, glist, new_vv, sig) = vs
            for ugid in prev_vv:
                if prev_vv[ugid] > new_vv[ugid]:
                    print("->[ERROR]: VSL not ordered")
                    return False
            prev_vv = new_vv
    print("->[INFO]: VSL is totally ordered.")

    #   2. Check that this user's previous VS matches the current one
    # TODO

    #   3. Verify the signatures
    #       - On first download, only verify the root
    #       - Load user itables as you go along
    global current_itables
    current_itables = {} # Build from scratch
    if only_check_root:
        print("->[INFO]: Only validating root's VS.")
        for vs in current_vsl:
            (uid, ihandle, ghandle_map, new_vv, sig) = vs
            data = (uid, ihandle, ghandle_map, new_vv)
            user = User(uid)
            if uid == 0:
                public_key = secfs.fs.usermap[user]
                if not secfs.crypto.verify(sig, public_key, pickle.dumps(data)):
                    print("->[ERROR]: Signature for root's VS does not match")
                    return False
                # Load the itable for this root only
                print("->[INFO]: Creating itable for root")
                current_itables[user] = Itable.load(ihandle)
                # Load its group tables
                for gid in ghandle_map:
                    print("->[INFO]: Creating itable for root group {}".format(gid))
                    current_itables[Group(gid)] = Itable.load(ghandle_map[gid])
    else:
        print("->[INFO]: Validating all VS's.")
        new_group_ihandles = {} # To store most up-to-date ghandles as we go along
        for vs in current_vsl:
            (uid, ihandle, ghandle_map, new_vv, sig) = vs
            data = (uid, ihandle, ghandle_map, new_vv)
            user = User(uid)
            if user in secfs.fs.usermap:
                public_key = secfs.fs.usermap[user]
                if not secfs.crypto.verify(sig, public_key, pickle.dumps(data)):
                    print("->[ERROR]: Signature for user {}'s VS does not match".format(uid))
                    return False
                # Load the itable for this user and update relevant group ihandles
                # since this VSL should be in sorted order
                print("->[INFO]: Creating itable for user {}".format(uid))
                current_itables[user] = Itable.load(ihandle)
                new_group_ihandles.update(ghandle_map)
            else:
                # If a user hasn't been mapped in usermap, that means it is not part
                # of a legitimate set of users as determined by root. This is bad since
                # this is a possibly rogue VS hiding in the VSL. Instead of ignoring it
                # we crash.
                raise Exception("->[ERROR]: Unmapped user {} in VSL!".format(uid))

        # Now load the group itables with the most recent group ihandles
        for gid in new_group_ihandles:
            print("->[INFO]: Creating itable for group {}".format(gid))
            current_itables[Group(gid)] = Itable.load(new_group_ihandles[gid])
    print("->[INFO]: Passed signature validation.")

    # Passed all tests
    return True

def pre(refresh, user, only_check_root=False, should_download=True):
    """
    Called before all user file system operations, right after we have obtained
    an exclusive server lock.
    """
    print("->[INFO]: User {} entering pre().".format(user))

    if not should_download:
        # secfs.fs.usermap probably not initialized yet, don't bother
        # downloading anything (just acquire the FS lock)
        print("->[INFO]: User {} exiting pre() without downloading VSL.\n".format(user))
        return

    # Pull the VSL and initialize I-Tables
    if download_vsl(only_check_root):
        # refresh user and group map AFTER setting up itables
        if refresh != None:
            print("->[INFO]: Calling {}.".format(refresh))
            refresh()
        # For the first time, after doing above initialization,
        # update the itables with now-trusted usermap and validate
        # the whole VSL rather than just root
        if only_check_root:
            download_vsl(False)
    else:
        print("->[ERROR]: Failed validation!")
        raise Exception("Failed validation")
    print("->[INFO]: User {} exiting pre().\n".format(user))

def post(push_vs, user):
    print("->[INFO]: User {} in post().".format(user))
    if not push_vs:
        # when creating a root, we should not push a VS (yet)
        # you will probably want to leave this here and
        # put your post() code instead of "pass" below.
        #f.write("[INFO]: User {} exited post() without pushing VSL.\n".format(user))
        print("->[INFO]: User {} exited post() without pushing VSL.".format(user))
        return

    global current_vsl, current_itables

    # Update version vector
    if len(current_vsl) > 0:
        new_vvector = dict(current_vsl[-1][3]) # Make a COPY!
    else:
        new_vvector = {}
    new_vvector[user.id] = new_vvector.get(user.id, 0) + 1
    # Store user's itable and upload if it doesnt exist
    uitable = current_itables.get(user, Itable())
    new_ihandle = secfs.store.block.store(uitable.bytes())
    # Do the same updates for groups
    groups = get_groups(user)
    new_ghandle_map = {}
    for group in groups:
        # Update the group version
        new_vvector[group.id] = new_vvector.get(group.id, 0) + 1
        # Store the new itable and upload if no exist
        gitable = current_itables.get(group, Itable())
        new_ghandle_map[group.id] = secfs.store.block.store(gitable.bytes())

    # Add signature
    data = (user.id, new_ihandle, new_ghandle_map, new_vvector)
    private_key = secfs.crypto.keys[user]
    sig = secfs.crypto.sign(private_key, pickle.dumps(data))

    # Create the new VS
    new_vs = (user.id, new_ihandle, new_ghandle_map, new_vvector, sig)
    print("->[INFO]: New {}.".format(print_vs(new_vs)))
    # Replace old entry in VSL, then upload new VSL
    new_vsl = [vs for vs in current_vsl if vs[0] != user.id]
    new_vsl.append(new_vs)
    current_vsl = new_vsl
    upload_vsl()

    # Issue garbage collection routine
    global garbage_ihashes
    secfs.store.block.remove(garbage_ihashes)
    garbage_ihashes = set()

    print("->[INFO]: User {} exiting post().\n".format(user))

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
    print("->[INFO]: Resolving {}, resolve_groups={}".format(i, resolve_groups))
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

def modunmap(mod_as, i):
    """
    Removes 'i' from all i-tables
    """
    print("->[INFO]: Unmapping {} in all itables, as user {}".format(i, mod_as))
    if not isinstance(i, I):
        raise TypeError("{} is not an I, is a {}".format(i, type(i)))
    if not isinstance(mod_as, User):
        raise TypeError("{} is not a User, is a {}".format(mod_as, type(mod_as)))

    assert mod_as.is_user() # only real users can mod

    global current_itables
    # Group i-table modification
    if i.p.is_group():
        # Save the real i on user's table
        real_i = resolve(i, False)
        # First unmap the group i
        group_t = current_itables[i.p]
        if i.n not in group_t.mapping:
            raise IndexError("(Unmapping) invalid inumber {} for group itable {}".format(i.n, group_t))
        # modify the entry, and store back the updated itable
        del group_t.mapping[i.n]
        current_itables[i.p] = group_t
        # Set 'i' for unlinking on user table
        i = real_i

    # User i-table modification
    user_t = current_itables[i.p]
    if i.n not in user_t.mapping:
        raise IndexError("(Unmapping) invalid inumber {} for user itable {}".format(i.n, user_t))
    # Flag the ihash to be garbage collected
    global garbage_ihashes
    garbage_ihashes.add(user_t.mapping[i.n])
    # Delete the reference from the itable
    del user_t.mapping[i.n]
    current_itables[i.p] = user_t

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
    print("->[INFO]: Modmapping {} to point to {}, as user {}".format(i, ihash, mod_as))
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
