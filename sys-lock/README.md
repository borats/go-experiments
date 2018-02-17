## sys-lock

Explore system wide locking for when resources need to be accessed
only once or at one place at a time using neat little domain sockets.

The idea is neat because it exploits the fact that unix domain sockets
under normal circumstances can only bind to a socket once. Next bind
will always *under normal circumstances* fail unless we use socket
trickeries; but that's not what we are exploring here :)