%% @author steenuil
%% @doc A low-level Erlang interface to the Linux `fanotify' API.
%%
%% [https://man7.org/linux/man-pages/man7/fanotify.7.html]
%%
%% This library focuses on receiving notifications for filesystem objects
%% and does not support intercepting events.
%%
%% @end

-module(fanotify).

-export([new/0, mark/4, read/2, close/1]).

-export_type([group/0, action/0, mask/0, event/0, info/0, file_handle/0]).

-nifs([{new_nif, 0}, {mark_nif, 4}, {read_nif, 2}, {close_nif, 1}]).

-on_load init/0.

%% Types

-opaque group() :: {fanotify_fd, non_neg_integer()}.
%% A fanotify group.
%%
%% Internally, this is represented as a file descriptor for the event queue
%% associated with the group.

-type action() ::
    add | remove | dont_follow | onlydir | ignored_mask | evictable | ignore.
%% Action to perform on the notification group.

-type mask() ::
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
%% Type of events that should be affected by the specified action.

-type event() :: {event, non_neg_integer(), [mask()], [info()]}.
%% Notification event.

-type info() ::
    {fid, file_handle()} |
    {dfid, file_handle()} |
    {dfid_name, file_handle(), binary()} |
    {new_dfid_name, file_handle(), binary()} |
    {old_dfid_name, file_handle(), binary()} |
    {unknown, non_neg_integer(), binary()}.
%% Additional event information.

-type file_handle() :: {file_handle, integer(), binary()}.
%% A file handle.

%% @doc Create a fanotify group.
%%
%% Currently the notification class supported is
%% `FAN_CLASS_NOTIF | FAN_REPORT_DFID_NAME', as the others require the
%% `CAP_SYS_ADMIN' capability.
-spec new() -> group() | {error, integer()}.
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
-spec mark(group(), string() | unicode:unicode_binary(), [action()], [mask()]) ->
              nil | {error, integer()}.
mark({fanotify_fd, Fd}, Path, Flags, Mask) ->
    mark_nif(Fd,
             prim_file:internal_name2native(Path),
             mark_flags(Flags, 0),
             mark_mask(Mask, 0)).

-spec mark_flags([action()], non_neg_integer()) -> non_neg_integer().
mark_flags([add | Rest], Flags) ->
    mark_flags(Rest, Flags bor 16#00000001);
mark_flags([remove | Rest], Flags) ->
    mark_flags(Rest, Flags bor 16#00000002);
mark_flags([dont_follow | Rest], Flags) ->
    mark_flags(Rest, Flags bor 16#00000004);
mark_flags([onlydir | Rest], Flags) ->
    mark_flags(Rest, Flags bor 16#00000008);
mark_flags([ignored_mask | Rest], Flags) ->
    mark_flags(Rest, Flags bor 16#00000020);
mark_flags([evictable | Rest], Flags) ->
    mark_flags(Rest, Flags bor 16#00000200);
mark_flags([ignore | Rest], Flags) ->
    mark_flags(Rest, Flags bor 16#00000400);
mark_flags([], Flags) ->
    Flags.

-spec mark_mask([mask()], non_neg_integer()) -> non_neg_integer().
mark_mask([access | Rest], Mask) ->
    mark_mask(Rest, Mask bor 16#00000001);
mark_mask([modify | Rest], Mask) ->
    mark_mask(Rest, Mask bor 16#00000002);
mark_mask([attrib | Rest], Mask) ->
    mark_mask(Rest, Mask bor 16#00000004);
mark_mask([close_write | Rest], Mask) ->
    mark_mask(Rest, Mask bor 16#00000008);
mark_mask([close_nowrite | Rest], Mask) ->
    mark_mask(Rest, Mask bor 16#00000010);
mark_mask([open | Rest], Mask) ->
    mark_mask(Rest, Mask bor 16#00000020);
mark_mask([moved_from | Rest], Mask) ->
    mark_mask(Rest, Mask bor 16#00000040);
mark_mask([moved_to | Rest], Mask) ->
    mark_mask(Rest, Mask bor 16#00000080);
mark_mask([create | Rest], Mask) ->
    mark_mask(Rest, Mask bor 16#00000100);
mark_mask([delete | Rest], Mask) ->
    mark_mask(Rest, Mask bor 16#00000200);
mark_mask([delete_self | Rest], Mask) ->
    mark_mask(Rest, Mask bor 16#00000400);
mark_mask([move_self | Rest], Mask) ->
    mark_mask(Rest, Mask bor 16#00000800);
mark_mask([open_exec | Rest], Mask) ->
    mark_mask(Rest, Mask bor 16#00001000);
mark_mask([fs_error | Rest], Mask) ->
    mark_mask(Rest, Mask bor 16#00008000);
mark_mask([open_perm | Rest], Mask) ->
    mark_mask(Rest, Mask bor 16#00010000);
mark_mask([access_perm | Rest], Mask) ->
    mark_mask(Rest, Mask bor 16#00020000);
mark_mask([open_exec_perm | Rest], Mask) ->
    mark_mask(Rest, Mask bor 16#00040000);
mark_mask([event_on_child | Rest], Mask) ->
    mark_mask(Rest, Mask bor 16#08000000);
mark_mask([rename | Rest], Mask) ->
    mark_mask(Rest, Mask bor 16#10000000);
mark_mask([ondir | Rest], Mask) ->
    mark_mask(Rest, Mask bor 16#40000000);
mark_mask([], Mask) ->
    Mask.

%% @doc Read the queued notification events on the notification group.
-spec read(group(), pos_integer()) -> [event()] | {error, integer()}.
read({fanotify_fd, Fd}, Count) ->
    case read_nif(Fd, Count) of
        {error, E} ->
            {error, E};
        {Len, Bytes} ->
            <<EventsBytes:Len/binary, _/binary>> = Bytes,
            parse_events(EventsBytes, [])
    end.

-spec parse_events(binary(), [event()]) -> [event()].
parse_events(<<>>, Events) ->
    Events;
parse_events(Bytes, Events) ->
    {Event, Rest} = parse_event(Bytes),
    parse_events(Rest, [Event | Events]).

-spec parse_event(binary()) -> {event(), binary()}.
parse_event(Bytes) ->
    <<EventLen:32/integer-unsigned-little,
      Version:8/integer,
      _Reserved:8/integer-unsigned-little,
      _MetadataLen:16/integer-unsigned-little,
      Mask:64/integer-unsigned-little,
      _Fd:32/integer-signed-little,
      _Pid:32/integer-signed-little,
      InfoBytes:(EventLen - 24)/binary,
      Rest/binary>> =
        Bytes,

    Infos = parse_info(InfoBytes, []),

    {{event, Version, parse_event_mask(Mask), Infos}, Rest}.

-spec parse_event_mask(integer()) -> [mask()].
parse_event_mask(Mask) ->
    parse_mask(Mask,
               [{access, 16#00000001},
                {modify, 16#00000002},
                {attrib, 16#00000004},
                {close_write, 16#00000008},
                {close_nowrite, 16#00000010},
                {open, 16#00000020},
                {moved_from, 16#00000040},
                {moved_to, 16#00000080},
                {create, 16#00000100},
                {delete, 16#00000200},
                {delete_self, 16#00000400},
                {move_self, 16#00000800},
                {open_exec, 16#00001000},
                {fs_error, 16#00008000},
                {open_perm, 16#00010000},
                {access_perm, 16#00020000},
                {open_exec_perm, 16#00040000},
                {event_on_child, 16#08000000},
                {rename, 16#10000000},
                {ondir, 16#40000000}]).

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

-define(FAN_EVENT_INFO_TYPE_FID, 1).
-define(FAN_EVENT_INFO_TYPE_DFID_NAME, 2).
-define(FAN_EVENT_INFO_TYPE_DFID, 3).
%% -define(FAN_EVENT_INFO_TYPE_PIDFD, 4).
%% -define(FAN_EVENT_INFO_TYPE_ERROR, 5).
%% -define(FAN_EVENT_INFO_TYPE_RANGE, 6).
-define(FAN_EVENT_INFO_TYPE_OLD_DFID_NAME, 10).
-define(FAN_EVENT_INFO_TYPE_NEW_DFID_NAME, 12).

-spec parse_info(binary(), [info()]) -> [info()].
parse_info(InfoBin, Infos) ->
    case parse_info(InfoBin) of
        nil ->
            Infos;
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
parse_info_type(?FAN_EVENT_INFO_TYPE_FID, HandleBytes) ->
    {Handle, <<>>} = parse_file_handle(HandleBytes),
    {fid, Handle};
parse_info_type(?FAN_EVENT_INFO_TYPE_DFID, HandleBytes) ->
    {Handle, <<>>} = parse_file_handle(HandleBytes),
    {dfid, Handle};
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

%% @doc Close the notification group, stopping the monitoring of events.
-spec close(group()) -> nil | {error, integer()}.
close({fanotify_fd, Fd}) ->
    close_nif(Fd).

%% NIFs here (beware)

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

-spec new_nif() -> non_neg_integer() | {error, integer()}.
new_nif() ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, ?LINE}]}).

-spec mark_nif(non_neg_integer(), binary(), non_neg_integer(), non_neg_integer()) ->
                  nil | {error, integer()}.
mark_nif(_, _, _, _) ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, ?LINE}]}).

-spec read_nif(non_neg_integer(), pos_integer()) ->
                  {non_neg_integer(), binary()} | {error, integer()}.
read_nif(_, _) ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, ?LINE}]}).

-spec close_nif(non_neg_integer()) -> nil | {error, integer()}.
close_nif(_) ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, ?LINE}]}).
