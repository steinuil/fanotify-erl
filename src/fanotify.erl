-module(fanotify).

-export([hello/0]).

-on_load init/0.

-define(APPNAME, fanotify).
-define(LIBNAME, fanotify).

init() ->
    SoName =
        case code:priv_dir(?APPNAME) of
            {error, bad_name} ->
                case filelib:is_dir(
                         filename:join(["..", priv]))
                of
                    true ->
                        filename:join(["..", priv, ?LIBNAME]);
                    _ ->
                        filename:join([priv, ?LIBNAME])
                end;
            Dir ->
                filename:join(Dir, ?LIBNAME)
        end,
    erlang:load_nif(SoName, 0).

hello() ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, ?LINE}]}).
