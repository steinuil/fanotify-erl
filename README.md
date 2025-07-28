# fanotify

A low-level Erlang interface to the Linux `fanotify` API.

This library **only works on Linux** and is **experimental**; I am not a great Erlang
programmer and this is the first Erlang library I publish; let alone the first time
I've written NIFs. Did I mention this library uses dirty NIFs?

The `0.x` version number is there for a reason. You have been warned.

## Build

```shell
$ rebar3 compile
```

## Usage

`fanotify` is an API that allows efficiently monitoring changes to many filesystem objects at once.

In practice, this means that you can monitor changes to files inside a set of directories
without spawning an external `inotifywatch` process.

```erlang
% Create a notification group.
Group = fanotify:new().

% Observe create and delete events on files inside /tmp/dir1
% and keep the file handle for later use.
nil = fanotify:mark(Group, "/tmp/dir1", [add, onlydir], [create, delete, ondir, event_on_child]).
Dir1Handle = fanotify:file_handle("/tmp/dir1").

% Also observe create and delete events on files inside /tmp/dir2.
nil = fanotify:mark(Group, "/tmp/dir2", [add, onlydir], [create, delete, ondir, event_on_child]).
Dir2Handle = fanotify:file_handle("/tmp/dir2").

% Receive filesystem events.
[{event, EventType, [{dfid_name, Handle, File}]}] = fanotify:read(Group).

case Handle of
    Dir1Handle ->
        io:format("Received ~w event on /tmp/dir1/~s~n", [EventType, File]);
    Dir2Handle ->
        io:format("Received ~w event on /tmp/dir2/~s~n", [EventType, File])
end.

% Close the notification group when done.
nil = fanotify:close(Group).
```
