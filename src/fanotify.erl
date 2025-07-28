%% @author steenuil
%% @doc A low-level Erlang interface to the Linux `fanotify' API.
%%
%% ```
%% % Create a notification group.
%% Group = fanotify:group().
%%
%% % Observe create and delete events on files inside /tmp/dir1
%% % and keep the file handle for later use.
%% nil = fanotify:mark(Group, "/tmp/dir1", [add, onlydir], [create, delete, ondir, event_on_child]).
%% Dir1Handle = fanotify:file_handle("/tmp/dir1").
%%
%% % Also observe create and delete events on files inside /tmp/dir2.
%% nil = fanotify:mark(Group, "/tmp/dir2", [add, onlydir], [create, delete, ondir, event_on_child]).
%% Dir2Handle = fanotify:file_handle("/tmp/dir2").
%%
%% % Receive filesystem events.
%% [{event, EventType, [{dfid_name, Handle, File}]}] = fanotify:read(Group).
%%
%% case Handle of
%%     Dir1Handle ->
%%         io:format("Received ~w event on /tmp/dir1/~s~n", [EventType, File]);
%%     Dir2Handle ->
%%         io:format("Received ~w event on /tmp/dir2/~s~n", [EventType, File])
%% end.
%%
%% % Close the notification group when done.
%% nil = fanotify:close(Group).
%% '''
%%
%% [https://man7.org/linux/man-pages/man7/fanotify.7.html]
%%
%% This library focuses on receiving notifications for filesystem objects
%% and does not support intercepting events.
%%
%% @end

-module(fanotify).

-export([new/0, mark/4, read/1, close/1, file_handle/1]).

-export_type([group/0, action/0, event_type/0, event/0, info/0, file_handle/0, posix/0]).

-nifs([{new_nif, 0},
       {mark_nif, 4},
       {read_nif, 2},
       {close_nif, 1},
       {name_to_handle_nif, 1}]).

-on_load init/0.

%%% -----------------------------------
%%% Type definitions

-doc """
A fanotify group.

Internally, this is represented as a file descriptor for the event queue
associated with the group.
""".
-opaque group() :: {fanotify_fd, non_neg_integer()}.

-doc """
Action to perform on the notification group.
""".
-type action() ::
    add | remove | dont_follow | onlydir | ignored_mask | evictable | ignore | flush.

-doc """
Type of event that occurred for a single filesystem object.
Corresponds to the bits on the `mask` argument on `fanotify_mark` and
to the `mask` field in the `fanotify_event_metadata` struct returned by
a `read(2)` on an fanotify file descriptor.
""".
-type event_type() ::
    access |
    modify |
    attrib |
    close_write |
    close_nowrite |
    open |
    moved_from |
    moved_to |
    create |
    delete |
    delete_self |
    move_self |
    open_exec |
    fs_error |
    open_perm |
    access_perm |
    open_exec_perm |
    event_on_child |
    rename |
    ondir.

-doc """
A notification for an event that occurred on a monitored filesystem object.
Corresponds to the `fanotify_event_metadata` struct returned by a `read(2)`
on an fanotify file descriptor.
""".
-type event() :: {event, [event_type()], [info()]}.

-doc """
Additional event information.

Corresponds to the `fanotify_event_info_fid` struct.
""".
-type info() ::
    {dfid_name, file_handle(), binary()} |
    {new_dfid_name, file_handle(), binary()} |
    {old_dfid_name, file_handle(), binary()} |
    {unknown, non_neg_integer(), binary()}.

-doc """
Filesystem object handle.

Can be used to identify the filesystem object that the event occurred on.
Corresponds to the `file_handle` struct returned by `name_to_handle_at`
""".
-opaque file_handle() :: {file_handle, integer(), binary()}.

-doc """
An atom representation of the `errno` value returned by a failed call
to one of the fanotify functions.
""".
-type posix() :: file:posix().

%%% -----------------------------------
%%% API functions

%% @doc Create a fanotify group.
%%
%% Currently the notification class supported is
%% `FAN_CLASS_NOTIF | FAN_REPORT_DFID_NAME', as the others require the
%% `CAP_SYS_ADMIN' capability.
-spec new() -> group() | {error, posix()}.
new() ->
    case new_nif() of
        {error, E} ->
            {error, E};
        Fd ->
            {fanotify_fd, Fd}
    end.

%% @doc Add, remove, or modify a fanotify mark on a filesystem object.
%%
%% The caller must have read permissions on the filesystem object that is
%% to be marked.
-spec mark(group(), string() | unicode:unicode_binary(), [action()], [event_type()]) ->
              nil | {error, posix()}.
mark({fanotify_fd, Fd}, Path, Action, EventTypes) ->
    mark_nif(Fd,
             prim_file:internal_name2native(Path),
             mark_flags(Action, 0),
             mark_mask(EventTypes, 0)).

%% @doc Read the queued notification events on the notification group.
%%
%% Returns a list of queued {@type event()}s containing `{event,[event_type()],[info()]}'.
%%
%% {@type info()} is a tuple containing `{Type, FileHandle, SubPath}', where
%% `Type' is one of `dfid_name', `new_dfid_name', or `old_dfid_name',
%% `FileHandle' is the file handle of the monitored filesystem object,
%% and `SubPath' is the subpath of the file that changes (when the monitored
%% object is a directory and `[ondir, event_on_child]' were specified in the `mark/4' call),
%% or `"."' when the watched object itself changed.
%%
%% Generally an {@type event()} only contains one {@type info()} with type `dfid_name',
%% except for the `rename' event which contains an `old_dfid_name ' and a `new_dfid_name',
%% respectively representing the old and the new name of the object that changed.
-spec read(group()) -> [event()] | {error, posix()}.
read({fanotify_fd, Fd}) ->
    case read_nif(Fd, 4096) of
        {error, E} ->
            {error, E};
        {Len, Bytes} ->
            <<EventsBytes:Len/binary, _/binary>> = Bytes,
            parse_events(EventsBytes, [])
    end.

%% @doc Close the notification group, stopping the monitoring of events.
-spec close(group()) -> nil | {error, posix()}.
close({fanotify_fd, Fd}) ->
    close_nif(Fd).

%% @doc Get the file handle for the filesystem object at the given path.
%%
%% A filesystem handle remains stable across calls, so you can use this to identify
%% which filesystem object received a notification when monitoring multiple
%% objects.
-spec file_handle(string() | unicode:unicode_binary()) ->
                     file_handle() | {error, posix() | nil}.
file_handle(Path) ->
    PathBin = prim_file:internal_name2native(Path),
    case name_to_handle_nif(PathBin) of
        {error, E} ->
            {error, E};
        HandleBin ->
            {Handle, <<>>} = parse_file_handle(HandleBin),
            Handle
    end.

%%% -----------------------------------
%%% NIFs here (beware)

init() ->
    SoName =
        case code:priv_dir(?MODULE) of
            {error, bad_name} ->
                case filelib:is_dir(
                         filename:join(["..", priv]))
                of
                    true ->
                        filename:join(["..", priv, ?MODULE]);
                    _ ->
                        filename:join([priv, ?MODULE])
                end;
            Dir ->
                filename:join(Dir, ?MODULE)
        end,
    erlang:load_nif(SoName, 0).

-spec new_nif() -> non_neg_integer() | {error, posix()}.
new_nif() ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, ?LINE}]}).

-spec mark_nif(non_neg_integer(), binary(), non_neg_integer(), non_neg_integer()) ->
                  nil | {error, posix()}.
mark_nif(_, _, _, _) ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, ?LINE}]}).

-spec read_nif(non_neg_integer(), pos_integer()) ->
                  {non_neg_integer(), binary()} | {error, posix()}.
read_nif(_, _) ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, ?LINE}]}).

-spec close_nif(non_neg_integer()) -> nil | {error, posix()}.
close_nif(_) ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, ?LINE}]}).

-spec name_to_handle_nif(binary()) -> binary() | {error, posix() | nil}.
name_to_handle_nif(_) ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, ?LINE}]}).

%%% -----------------------------------
%%% Constants

%% We only support parsing event metadata version 3.
-define(FANOTIFY_METADATA_VERSION, 3).

%% Types of events that we can receive.
%% -define(FAN_EVENT_INFO_TYPE_FID, 1).
-define(FAN_EVENT_INFO_TYPE_DFID_NAME, 2).
%% -define(FAN_EVENT_INFO_TYPE_DFID, 3).
%% -define(FAN_EVENT_INFO_TYPE_PIDFD, 4).
%% -define(FAN_EVENT_INFO_TYPE_ERROR, 5).
%% -define(FAN_EVENT_INFO_TYPE_RANGE, 6).
-define(FAN_EVENT_INFO_TYPE_OLD_DFID_NAME, 10).
-define(FAN_EVENT_INFO_TYPE_NEW_DFID_NAME, 12).

%% Types of events that userspace can register for.
-define(FAN_ACCESS, 16#00000001).
-define(FAN_MODIFY, 16#00000002).
-define(FAN_ATTRIB, 16#00000004).
-define(FAN_CLOSE_WRITE, 16#00000008).
-define(FAN_CLOSE_NOWRITE, 16#00000010).
-define(FAN_OPEN, 16#00000020).
-define(FAN_MOVED_FROM, 16#00000040).
-define(FAN_MOVED_TO, 16#00000080).
-define(FAN_CREATE, 16#00000100).
-define(FAN_DELETE, 16#00000200).
-define(FAN_DELETE_SELF, 16#00000400).
-define(FAN_MOVE_SELF, 16#00000800).
-define(FAN_OPEN_EXEC, 16#00001000).
%% -define(FAN_Q_OVERFLOW, 16#00004000).
-define(FAN_FS_ERROR, 16#00008000).
-define(FAN_OPEN_PERM, 16#00010000).
-define(FAN_ACCESS_PERM, 16#00020000).
-define(FAN_OPEN_EXEC_PERM, 16#00040000).
%% -define(FAN_PRE_ACCESS, 16#00100000).
-define(FAN_EVENT_ON_CHILD, 16#08000000).
-define(FAN_RENAME, 16#10000000).
-define(FAN_ONDIR, 16#40000000).

% Actions that we can perform on a group.
-define(FAN_MARK_ADD, 16#00000001).
-define(FAN_MARK_REMOVE, 16#00000002).
-define(FAN_MARK_DONT_FOLLOW, 16#00000004).
-define(FAN_MARK_ONLYDIR, 16#00000008).
-define(FAN_MARK_IGNORED_MASK, 16#00000020).
%% -define(FAN_MARK_IGNORED_SURV_MODIFY, 16#00000040).
-define(FAN_MARK_FLUSH, 16#00000080).
-define(FAN_MARK_EVICTABLE, 16#00000200).
-define(FAN_MARK_IGNORE, 16#00000400).

%%% -----------------------------------
%%% Serializing

-spec mark_flags([action()], non_neg_integer()) -> non_neg_integer().
mark_flags([add | Rest], Flags) ->
    mark_flags(Rest, Flags bor ?FAN_MARK_ADD);
mark_flags([remove | Rest], Flags) ->
    mark_flags(Rest, Flags bor ?FAN_MARK_REMOVE);
mark_flags([dont_follow | Rest], Flags) ->
    mark_flags(Rest, Flags bor ?FAN_MARK_DONT_FOLLOW);
mark_flags([onlydir | Rest], Flags) ->
    mark_flags(Rest, Flags bor ?FAN_MARK_ONLYDIR);
mark_flags([ignored_mask | Rest], Flags) ->
    mark_flags(Rest, Flags bor ?FAN_MARK_IGNORED_MASK);
mark_flags([evictable | Rest], Flags) ->
    mark_flags(Rest, Flags bor ?FAN_MARK_EVICTABLE);
mark_flags([ignore | Rest], Flags) ->
    mark_flags(Rest, Flags bor ?FAN_MARK_IGNORE);
mark_flags([flush | Rest], Flags) ->
    mark_flags(Rest, Flags bor ?FAN_MARK_FLUSH);
mark_flags([], Flags) ->
    Flags.

-spec mark_mask([event_type()], non_neg_integer()) -> non_neg_integer().
mark_mask([access | Rest], Mask) ->
    mark_mask(Rest, Mask bor ?FAN_ACCESS);
mark_mask([modify | Rest], Mask) ->
    mark_mask(Rest, Mask bor ?FAN_MODIFY);
mark_mask([attrib | Rest], Mask) ->
    mark_mask(Rest, Mask bor ?FAN_ATTRIB);
mark_mask([close_write | Rest], Mask) ->
    mark_mask(Rest, Mask bor ?FAN_CLOSE_WRITE);
mark_mask([close_nowrite | Rest], Mask) ->
    mark_mask(Rest, Mask bor ?FAN_CLOSE_NOWRITE);
mark_mask([open | Rest], Mask) ->
    mark_mask(Rest, Mask bor ?FAN_OPEN);
mark_mask([moved_from | Rest], Mask) ->
    mark_mask(Rest, Mask bor ?FAN_MOVED_FROM);
mark_mask([moved_to | Rest], Mask) ->
    mark_mask(Rest, Mask bor ?FAN_MOVED_TO);
mark_mask([create | Rest], Mask) ->
    mark_mask(Rest, Mask bor ?FAN_CREATE);
mark_mask([delete | Rest], Mask) ->
    mark_mask(Rest, Mask bor ?FAN_DELETE);
mark_mask([delete_self | Rest], Mask) ->
    mark_mask(Rest, Mask bor ?FAN_DELETE_SELF);
mark_mask([move_self | Rest], Mask) ->
    mark_mask(Rest, Mask bor ?FAN_MOVE_SELF);
mark_mask([open_exec | Rest], Mask) ->
    mark_mask(Rest, Mask bor ?FAN_OPEN_EXEC);
mark_mask([fs_error | Rest], Mask) ->
    mark_mask(Rest, Mask bor ?FAN_FS_ERROR);
mark_mask([open_perm | Rest], Mask) ->
    mark_mask(Rest, Mask bor ?FAN_OPEN_PERM);
mark_mask([access_perm | Rest], Mask) ->
    mark_mask(Rest, Mask bor ?FAN_ACCESS_PERM);
mark_mask([open_exec_perm | Rest], Mask) ->
    mark_mask(Rest, Mask bor ?FAN_OPEN_EXEC_PERM);
mark_mask([event_on_child | Rest], Mask) ->
    mark_mask(Rest, Mask bor ?FAN_EVENT_ON_CHILD);
mark_mask([rename | Rest], Mask) ->
    mark_mask(Rest, Mask bor ?FAN_RENAME);
mark_mask([ondir | Rest], Mask) ->
    mark_mask(Rest, Mask bor ?FAN_ONDIR);
mark_mask([], Mask) ->
    Mask.

%%% -----------------------------------
%%% Struct parsing

-spec parse_event_mask(integer()) -> [event_type()].
parse_event_mask(Mask) ->
    parse_mask(Mask,
               [{access, ?FAN_ACCESS},
                {modify, ?FAN_MODIFY},
                {attrib, ?FAN_ATTRIB},
                {close_write, ?FAN_CLOSE_WRITE},
                {close_nowrite, ?FAN_CLOSE_NOWRITE},
                {open, ?FAN_OPEN},
                {moved_from, ?FAN_MOVED_FROM},
                {moved_to, ?FAN_MOVED_TO},
                {create, ?FAN_CREATE},
                {delete, ?FAN_DELETE},
                {delete_self, ?FAN_DELETE_SELF},
                {move_self, ?FAN_MOVE_SELF},
                {open_exec, ?FAN_OPEN_EXEC},
                {fs_error, ?FAN_FS_ERROR},
                {open_perm, ?FAN_OPEN_PERM},
                {access_perm, ?FAN_ACCESS_PERM},
                {open_exec_perm, ?FAN_OPEN_EXEC_PERM},
                {event_on_child, ?FAN_EVENT_ON_CHILD},
                {rename, ?FAN_RENAME},
                {ondir, ?FAN_ONDIR}]).

-spec parse_events(binary(), [event()]) -> [event()].
parse_events(<<>>, Events) ->
    lists:reverse(Events);
parse_events(Bytes, Events) ->
    {Event, Rest} = parse_event(Bytes),
    parse_events(Rest, [Event | Events]).

-spec parse_event(binary()) -> {event(), binary()}.
parse_event(Bytes) ->
    <<EventLen:32/integer-unsigned-little,
      ?FANOTIFY_METADATA_VERSION:8/integer,
      _Reserved:8/integer-unsigned-little,
      _MetadataLen:16/integer-unsigned-little,
      Mask:64/integer-unsigned-little,
      _Fd:32/integer-signed-little,
      _Pid:32/integer-signed-little,
      InfoBytes:(EventLen - 24)/binary,
      Rest/binary>> =
        Bytes,

    Infos = parse_info(InfoBytes, []),

    {{event, parse_event_mask(Mask), Infos}, Rest}.

-spec parse_info(binary(), [info()]) -> [info()].
parse_info(InfoBin, Infos) ->
    case parse_info(InfoBin) of
        nil ->
            lists:reverse(Infos);
        {Info, Rest} ->
            parse_info(Rest, [Info | Infos])
    end.

-spec parse_info(binary()) -> {info(), binary()} | nil.
parse_info(<<>>) ->
    nil;
parse_info(<<InfoType:8/integer,
             _InfoPad:8/integer,
             InfoLen:16/integer-unsigned-little,
             _Fsid:64/integer,
             InfoBytes:(InfoLen - 12)/binary,
             Rest/binary>>) ->
    Info = parse_info_type(InfoType, InfoBytes),
    {Info, Rest}.

-spec parse_info_type(non_neg_integer(), binary()) -> info().
parse_info_type(?FAN_EVENT_INFO_TYPE_DFID_NAME, HandleBytes) ->
    {Handle, NameS} = parse_file_handle(HandleBytes),
    Name = parse_zero_terminated_string(NameS, 0),
    {dfid_name, Handle, Name};
parse_info_type(?FAN_EVENT_INFO_TYPE_NEW_DFID_NAME, HandleBytes) ->
    {Handle, NameS} = parse_file_handle(HandleBytes),
    Name = parse_zero_terminated_string(NameS, 0),
    {new_dfid_name, Handle, Name};
parse_info_type(?FAN_EVENT_INFO_TYPE_OLD_DFID_NAME, HandleBytes) ->
    {Handle, NameS} = parse_file_handle(HandleBytes),
    Name = parse_zero_terminated_string(NameS, 0),
    {old_dfid_name, Handle, Name};
parse_info_type(Type, Bytes) ->
    {unknown, Type, Bytes}.

-spec parse_file_handle(binary()) -> {file_handle(), binary()}.
parse_file_handle(<<Len:32/integer-unsigned-little,
                    Type:32/integer-signed-little,
                    Handle:Len/binary,
                    Rest/binary>>) ->
    {{file_handle, Type, Handle}, Rest}.

%%% -----------------------------------
%%% Generic parsing

-spec parse_mask(integer(), [{atom(), integer()}]) -> [atom()].
parse_mask(Mask, Spec) ->
    lists:foldl(fun({Name, Bit}, Acc) ->
                   case Mask band Bit =/= 0 of
                       true -> [Name | Acc];
                       false -> Acc
                   end
                end,
                [],
                Spec).

-spec parse_zero_terminated_string(binary(), non_neg_integer()) -> binary().
parse_zero_terminated_string(Bin, Length) ->
    case Bin of
        <<Str:Length/binary, 0, _/binary>> ->
            Str;
        <<_:Length/binary>> ->
            <<>>;
        _ ->
            parse_zero_terminated_string(Bin, Length + 1)
    end.
