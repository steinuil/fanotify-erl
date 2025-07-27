-module(fanotify).

-export([new/0, mark/4, read/2, close/1]).

-nifs([{new_nif, 0}, {mark_nif, 4}, {read_nif, 2}, {close_nif, 1}]).

-on_load init/0.

new() ->
    case new_nif() of
        {error, E} ->
            {error, E};
        Fd ->
            {fanotify_fd, Fd}
    end.

mark({fanotify_fd, Fd}, Path, Flags, Mask) ->
    mark_nif(Fd,
             prim_file:internal_name2native(Path),
             mark_flags(Flags, 0),
             mark_mask(Mask, 0)).

mark_flags([add | Rest], Flags) ->
    mark_flags(Rest, Flags bor 16#00000001);
mark_flags([remove | Rest], Flags) ->
    mark_flags(Rest, Flags bor 16#00000002);
mark_flags([dont_follow | Rest], Flags) ->
    mark_flags(Rest, Flags bor 16#00000004);
mark_flags([only_dir | Rest], Flags) ->
    mark_flags(Rest, Flags bor 16#00000008);
mark_flags([ignored_mask | Rest], Flags) ->
    mark_flags(Rest, Flags bor 16#00000020);
mark_flags([evictable | Rest], Flags) ->
    mark_flags(Rest, Flags bor 16#00000200);
mark_flags([ignore | Rest], Flags) ->
    mark_flags(Rest, Flags bor 16#00000400);
mark_flags([], Flags) ->
    Flags.

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

read({fanotify_fd, Fd}, Count) ->
    case read_nif(Fd, Count) of
        {error, E} ->
            {error, E};
        {BytesLen, AllBytes} ->
            <<Bytes:BytesLen/binary, _/binary>> = AllBytes,

            <<EventLen:32/integer-unsigned-little,
              Version:8/integer-unsigned-little,
              _Reserved:8/integer-unsigned-little,
              MetadataLen:16/integer-unsigned-little,
              Mask:64/integer-unsigned-little,
              _Fd:32/integer-unsigned-little,
              _Pid:32/integer-unsigned-little,
              _/binary>> =
                Bytes,
            nil
    end.

parse_event(Bytes) ->
    <<_EventLen:32/integer-unsigned-little,
      Version:8/integer,
      _Reserved:8/integer-unsigned-little,
      _MetadataLen:16/integer-unsigned-little,
      Mask:64/integer-unsigned-little,
      _Fd:32/integer-unsigned-little,
      _Pid:32/integer-unsigned-little,
      Rest/bytes>> =
        Bytes,

    %% Info = case Rest of
    %%     <<>> -> none;
    %%     <<
    %%         InfoType:8/integer,
    %%         _InfoPad:8/integer,
    %%         _InfoLen:16/integer-unsigned-little,
    %%     >>
    %% end
    %%     InfoType:8/integer,
    %%     _InfoPad:8/integer,
    %%     _InfoLen:16/integer-unsigned-little,
    %%     Fsid:64/integer-unsigned-little,
    %%     FileHandleLen:32/integer-unsigned-little,
    %%     FileHandleType:32/integer-signed-little,
    %%     FileHandle:FileHandleLen/binary,
    %%     _/binary
    %% >> = Bytes,
    {event, Version, Mask}. %, InfoType, Fsid, FileHandleType, FileHandle}.

parse_info(<<>>) ->
    none;
parse_info(<<InfoType:8/integer, _InfoPad:8/integer, InfoLen:16/integer, _/binary>>) ->
    some.

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

new_nif() ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, ?LINE}]}).

mark_nif(_, _, _, _) ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, ?LINE}]}).

read_nif(_, _) ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, ?LINE}]}).

close_nif(_) ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, ?LINE}]}).
