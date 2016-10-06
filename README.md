# SecFS - A secure and concurrent file-system

## Introduction

The world is slowly becoming more connected, and there's an increasing
need to have all your data be available, shareable, secure, and
replicated. Because of this need, cloud services such as Dropbox and
Google Drive have emerged, and become wildly successful. They take your
files and transparently host them in "the cloud". Unfortunately, users
lose some measure of control over that data in the process. You have to
trust your data to these companies; you have to trust them not to look
at your data, not to share it, and not to lose it. The goal of SecFS is
for users to be able to store data on a remote file server, without
having to trust that server, obviating many of these problems.

The contents of this project are largely influenced by the ["Secure Untrusted Data Repository (SUNDR)"](https://www.usenix.org/legacy/event/osdi04/tech/full_papers/li_j/li_j.pdf) paper by Li et. al.

## Code Structure

 File/directory     | Purpose
--------------------|--------
 `setup.sh`         | Script to modify the course VM to run SecFS
 `setup.py`         | Used to install various Python dependencies
 `start.sh`         | Start the server and a single client mounted at `mnt/`
 `stop.sh`          | Stop the server and any active clients
 `secfs/`           | Contains the bulk of the implementation of SecFS
 `bin/secfs-fuse`   | Mounts SecFS as a FUSE mountpoint so it can be accessed through the file system
 `bin/secfs-server` | Runs the (untrusted) SecFS server
 `venv/`            | Directory for creating Python [virtual environments](https://docs.python.org/3/library/venv.html)
 `*.log`            | Log files from the server and various clients spawned during the tests
 `*.err`            | Error log files from the server and clients
 `secfs-test.*/`    | Working directories for tests. Can be safely deleted.
 `*.pem` + `*.pub`  | Automatically generated private and public keys for users

### Interacting with SecFS

To start the SecFS server and client, run `./start.sh`. This will mount
a single FUSE client on the directory `./mnt/`.

```
mkdir mnt2
sudo venv/bin/secfs-fuse PYRO:secfs@./u:server.sock mnt2/ root.pub user-0-key.pem "user-$(id -u)-key.pem" > client.log &
```

You should now be able to cd into `mnt/` and poke around. For example,
try running `ls -la`, and look for the files `.users` and `.groups`.
There are a couple of things you should be aware of when interacting
with this file system:

 - SUNDR (and so our file system) does not follow standard UNIX file and
   directory permissions. In particular, the read and write permissions
   of files and directories are cryptographically enforced, and cannot
   be changed using chmod/chown.
 - Only the user or group that owns a directory may create new entries
   in that directory. Since `/` (inside `mnt/`) is owned by the root
   user by default, only root can create new files in it. Thus, trying
   to run `touch mnt/x` as a regular user will *not* work. You will need
   to do `sudo touch mnt/x`.
 - SecFS only supports a limited subset of file-system operations, so
   certain commands may give strange-looking "Function not implemented"
   errors. For example, since the removal of a file is not implemented,
   calling `rm` will fail. Do not fret, this is expected behavior.

### Stop / Cleanup SecFS Server

To clean up the server, clients, and the `mnt/` mountpoint, run
`./stop.sh`.

## The SecFS System

SecFS consists of two primary components: a FUSE client
(`bin/secfs-fuse`), and a storage server (`bin/secfs-server`), which
communicate over RPC. SecFS's design is heavily inspired by SUNDR, and
borrows many of the structures used therein. Specifically, the file
system is organized around the notion of `i`-pairs, or `i`s for short.
An `i`-pair is a tuple containing a principal identity (i.e. a `User` or
`Group`, both mapped to a UNIX ID), and a file number. `i`-pairs are
represented using the class `I`. These types are all defined in
`secfs/types.py`. The server uses the two special files `/.users` and
`/.groups` to store and recover the mapping from user ID to public key
and from group ID to user IDs respectively. This loading is performed by
`_reload_principals()` in `bin/secfs-fuse`.

In SUNDR, every user also has an `i`-table, hosted by the server, which
maps each of their file numbers to a block hash. This is illustrated in
Figure 2 in the paper. In the skeleton code we give you, these tables
are stored locally in a simple Python dictionary.  These block hashes
can be sent to the server, and the block contents (which can be verified
using the hash) will be returned. Groups have `i`-table similar to
users, but instead of mapping to block hashes, they map to a second,
user-owned, `i`, which can then be resolved to reach the file contents.
This indirection allows all members of a particular group to update a
shared file while retaining the ability to verify the authenticity of
all operations.

   structure         | location
   ------------------|---------
   i-tables          | `secfs/tables.py`
   inodes            | `secfs/store/inode.py`
   directory block   | `secfs/store/tree.py`

In SecFS, files and directories both consist of an inode structure (in
`secfs/store/inode.py`) holding various metadata about each file, and a
list of block hashes that, when fetched and concatenated, make up the
contents of the file. Directories are lists of name/`i` pairs, which can
be resolved and fetched recursively to explore the file-system tree.
Files are updated by sending new blobs to the server, and then updating
the `i`-table of the owning principal so that the `i` of the file that is
being changed points to the new signature.

The SecFS server's job is little more than to store blobs that it
receives from clients, and serve these back to clients that request
them. Some of these blobs also contain the `i`-table, as well as the
information needed to resolve group memberships, but this is not managed
by the server.

All the magic is in the SecFS FUSE client. It connects to the server,
and starts by requesting the `i` of the root of the file system. From
there, it can use the aforementioned mechanisms to follow links further
down in the file system.

Here are the primary specifications for the SecFS system:

 - Users can create, read, and write files.
 - The file system supports directories, much like the Unix file system.
 - Users should be able to set permissions on files and directories,
   which also requires that your file system be able to name users.
 - Multiple concurrent users, all connected to the server through
   *different* clients, should be able to share files with one another.
   In particular, when a file is created, it should be made either user-
   or group-writeable, and users should be able to limit the
   read-permissions for that file in such a way that only those who can
   write the file can read it. *You are not require to keep these two
   lists in sync or up to date --- if a user is later added to a group
   owning a particular group-readable file, it is fine if they are not
   able to read or write that file*.
 - File names (and directory names) should be treated as confidential.
   That is, a user should be able to read-protect an entire directory,
   and not leak file or directory names within that directory.
 - Users should not be able to modify files or directories without being
   detected, unless they are authorized to do so.
 - Neither the server, nor any user not mentioned in a file's ACL,
   should be able to read plain text file contents, file names, or
   directory names, even if the server and the unprivileged users
   collude. World-readable files can naturally be read by everyone
   (including the server). To effect this, you will need to encrypt
   files and come up with a secure way to distribute the keys for each
   file to only those named on its ACL.
 - The server should not be able to take data from one file and supply
   it in response to a client reading a different file. In particular, a
   client should always be able to detect if it is not being supplied
   data that has been written by a user with write permissions for the
   file in question. Note that this does *not* cover the case of the
   server serving _stale_ data, which we do not require you to detect.
 - A malicious file server should not be able to create, modify, or
   delete files and directories without being detected. 

Some improvements that have been added in this particular implementation:
 - A client should never see an older version of a file after it sees a newer one. This is equivalent to the "strong fork consistency" guarantee as mentioned in the SUNDR paper. 
 - After long continuous use, the SecFS server will accumulate a lot of
   hash blocks are that unused, so there is a garbage collection routine to
   periodically clean out unused data.
 - The list of principals and permissions for any given file/directory are
   entirely hidden from non-authenticated principals.
 - SecFS supports key revocation - to invalidate and create a new secure key
   for any particular user/group.

**Creating group-owned files/directories.**
The way we let users create group-writeable files in SecFS (i.e.
through FUSE) is by abusing the user's
[`umask(2)`](http://man7.org/linux/man-pages/man2/umask.2.html). The
umask of a process determines what permissions will *not* be granted to
newly created files. For example, by setting your umask to `0200`, you
are saying that new files should have all bits set *except* the owner's
write bit. SecFS interprets this as making the file group-writeable.
Note that using `0200` will cause the file to shared with the group the
user is currently running as; for root, this is usually group 0, so you
will want to use the `sg` command to instead operate as the "users"
group (group 100).
