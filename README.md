# SIRS Project Server

Server-side solution of the SIRS (Computer And Network Security) course project. You can find the client side at [sirs-project-android-client](https://github.com/iluxonchik/sirs-project-android-client).

This README was written more than a year after the project has been completed, so this is is just a quick overview. There
is no PDF with the description of the project, because it was self-proposed.

The idea was to create an appplication that encyrpts all of the files in a folder when the user leaves the computer and
decrypts them when he comes back. This is done automatically, whithout requiring any action from him.

To know if the user has left/entered the vicinity of his computer, bluetooth was used. Here is how the system works:

* the server runs a bluetooth server that is constantly awaiting for a connection
* the mobile application is running a bluetooth client that is constantly trying to connect to the server
* when the client connects to the server, the files are decrypted
* when the client disconnects from the server (becaue the user goes away), the files are encrypted

You can find some [justifications for the decisions that were taken here](https://github.com/iluxonchik/sirs-project-server/blob/master/docs/notes/notes.md).
