-module(aestratum_utils).

-export([timestamp/0]).

-export([is_hex/1,
         is_valid_string/1
        ]).

-export([hex_to_bin/1]).

-export_type([timestamp/0]).

-type timestamp() :: pos_integer().

%% Timestamp in milliseconds.
-spec timestamp() -> timestamp().
timestamp() ->
    {MegaSecs, Secs, MicroSecs} = os:timestamp(),
    (MegaSecs * 1000000 + Secs) * 1000 + erlang:trunc(MicroSecs / 1000).

-spec is_hex(binary()) -> boolean().
is_hex(Bin) when is_binary(Bin) ->
    lists:all(fun(Byte) when Byte >= $0, Byte =< $9 -> true;
                 (Byte) when Byte >= $a, Byte =< $f -> true;
                 (Byte) when Byte >= $A, Byte =< $F -> true;
                 (_Byte) -> false end, binary_to_list(Bin)).

-spec is_valid_string(binary()) -> boolean().
is_valid_string(Bin) when is_binary(Bin) ->
    lists:all(fun(Byte) when Byte =:= $\s -> false;
                 (Byte) when Byte =:= $\n -> false;
                 (Byte) when Byte =:= $\t -> false;
                 (Byte) when Byte =:= $\v -> false;
                 (Byte) when Byte =:= $\f -> false;
                 (Byte) when Byte =:= $\r -> false;
                 (_Byte) -> true end, binary_to_list(Bin)).

-spec hex_to_bin(binary()) -> binary().
hex_to_bin(S) ->
    hex_to_bin(binary_to_list(S), []).

hex_to_bin([], Acc) ->
    list_to_binary(lists:reverse(Acc));
hex_to_bin([X, Y | T], Acc) ->
    {ok, [V], []} = io_lib:fread("~16u", [X, Y]),
    hex_to_bin(T, [V | Acc]).

