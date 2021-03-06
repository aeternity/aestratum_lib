-module(aestratum_nonce_tests).

-include_lib("eunit/include/eunit.hrl").

-define(TEST_MODULE, aestratum_nonce).

nonce_test_() ->
    [new(badarg_nonce),
     new(badarg_part_nonce),
     new(valid_nonce),
     new(valid_part_nonce),
     to_hex(badarg),
     to_hex(valid_nonce),
     to_hex(valid_part_nonce),
     to_int(badarg_nonce),
     to_int(badarg_part_nonce),
     to_int(valid_nonce),
     to_int(valid_part_nonce),
     is_valid_bin(badarg_nonce),
     is_valid_bin(valid_nonce),
     is_valid_bin(badarg_part_nonce),
     is_valid_bin(valid_part_nonce),
     max(badarg),
     max_value(badarg),
     max_value(valid),
     merge(badarg),
     merge(valid),
     split(badarg),
     split(valid),
     update(badarg),
     type(badarg),
     type(valid),
     value(badarg),
     value(valid),
     nbytes(badarg),
     nbytes(valid),
     complement_nbytes(badarg),
     complement_nbytes(valid)].

new(badarg_nonce) ->
    L = [atom, [], -1, -1.0, <<>>, 16#ffffffffffffffff + 1],
    [?_assertException(error, badarg, ?TEST_MODULE:new(I)) || I <- L];
new(badarg_part_nonce) ->
    L = [{x, y, z}, {0, 1, 1}, {unknown_type, 1000, 5},
         {extra, -1, 4}, {extra, 1.0, 1}, {miner, 0, 0},
         {extra, 1, 8}, {miner, -1, 0}, {miner, 4, 16#ffffffff + 1}],
    [?_assertException(error, badarg, ?TEST_MODULE:new(T, I, N)) || {T, I, N} <- L];
new(valid_nonce) ->
    [?_assertEqual(<<"0000000000000000">>, ?TEST_MODULE:to_hex(?TEST_MODULE:new(0))),
     ?_assertEqual(<<"0100000000000000">>, ?TEST_MODULE:to_hex(?TEST_MODULE:new(1))),
     ?_assertEqual(<<"0f00000000000000">>, ?TEST_MODULE:to_hex(?TEST_MODULE:new(16#f))),
     ?_assertEqual(<<"ff00000000000000">>, ?TEST_MODULE:to_hex(?TEST_MODULE:new(16#ff))),
     ?_assertEqual(<<"f101ff0000000000">>, ?TEST_MODULE:to_hex(?TEST_MODULE:new(16#ff01f1))),
     ?_assertEqual(<<"4523010000000000">>, ?TEST_MODULE:to_hex(?TEST_MODULE:new(16#012345)))];
new(valid_part_nonce) ->
    [?_assertEqual(<<"00">>, ?TEST_MODULE:to_hex(?TEST_MODULE:new(miner, 0, 1))),
     ?_assertEqual(<<"0100">>, ?TEST_MODULE:to_hex(?TEST_MODULE:new(extra, 1, 2))),
     ?_assertEqual(<<"ff0000">>, ?TEST_MODULE:to_hex(?TEST_MODULE:new(extra, 16#ff, 3))),
     ?_assertEqual(<<"0f000000">>, ?TEST_MODULE:to_hex(?TEST_MODULE:new(extra, 16#f, 4))),
     ?_assertEqual(<<"0a010f00000000">>, ?TEST_MODULE:to_hex(?TEST_MODULE:new(miner, 16#0f010a, 7)))].

to_hex(badarg) ->
    L = [foo, {}, <<>>, 1000, 0.0, -1],
    [?_assertException(error, badarg, ?TEST_MODULE:to_hex(I)) || I <- L];
to_hex(valid_nonce) ->
    [?_assertEqual(<<"0000000000000000">>, ?TEST_MODULE:to_hex(?TEST_MODULE:new(0))),
     ?_assertEqual(<<"0807060504030201">>, ?TEST_MODULE:to_hex(?TEST_MODULE:new(16#0102030405060708))),
     ?_assertEqual(<<"ffffffff00000000">>, ?TEST_MODULE:to_hex(?TEST_MODULE:new(16#ffffffff)))];
to_hex(valid_part_nonce) ->
    [?_assertEqual(<<"00">>, ?TEST_MODULE:to_hex(?TEST_MODULE:new(extra, 0, 1))),
     ?_assertEqual(<<"0a0b">>, ?TEST_MODULE:to_hex(?TEST_MODULE:new(miner, 16#0b0a, 2))),
     ?_assertEqual(<<"04030201">>, ?TEST_MODULE:to_hex(?TEST_MODULE:new(miner, 16#01020304, 4)))].

to_int(badarg_nonce) ->
    L = [<<>>, <<"00">>, 16#ff, [],
         <<"010203040506070">>, <<"0102030405060708f">>],
    [?_assertException(error, badarg, ?TEST_MODULE:to_int(B)) || B <- L];
to_int(badarg_part_nonce) ->
    L = [{no_type, <<"00">>, 1}, {extra, <<>>, 1}, {miner, <<"0">>, 1},
         {miner, <<"111">>, 2}, {extra, [], 5}, {extra, <<"01020304050607">>, 8},
         {extra, <<"0102030405060708">>, 8}],
    [?_assertException(error, badarg, ?TEST_MODULE:to_int(T, B, N)) || {T, B, N} <- L];
to_int(valid_nonce) ->
    [?_assertEqual(0, ?TEST_MODULE:to_int(<<"0000000000000000">>)),
     ?_assertEqual(16#abcdef, ?TEST_MODULE:to_int(<<"efcdab0000000000">>)),
     ?_assertEqual(16#0101010102020202, ?TEST_MODULE:to_int(<<"0202020201010101">>))
    ];
to_int(valid_part_nonce) ->
    [?_assertEqual(0, ?TEST_MODULE:to_int(miner, <<"00">>, 1)),
     ?_assertEqual(16#ab, ?TEST_MODULE:to_int(miner, <<"ab000000">>, 4)),
     ?_assertEqual(16#1020304000, ?TEST_MODULE:to_int(miner, <<"0040302010">>, 5))].

is_valid_bin(badarg_nonce) ->
    L = [{foo, bar}, 10, atom, "", "11223344"],
    [?_assertException(error, badarg, ?TEST_MODULE:is_valid_bin(B)) || B <- L];
is_valid_bin(valid_nonce) ->
    [?_assertEqual(false, ?TEST_MODULE:is_valid_bin(<<"112233445566778X">>)),
     ?_assertEqual(true, ?TEST_MODULE:is_valid_bin(<<"1122334455667788">>))];
is_valid_bin(badarg_part_nonce) ->
    L = [{invalid_type, <<"11">>, 1}, {<<>>, 1, atom}, {1, foo, bar},
         {miner, "1234", 4}, {extra, [], 5}, {miner, <<"1111">>, 8}],
    [?_assertException(error, badarg, ?TEST_MODULE:is_valid_bin(T, B, N)) || {T, B, N} <- L];
is_valid_bin(valid_part_nonce) ->
    [?_assertEqual(false, ?TEST_MODULE:is_valid_bin(miner, <<"aabbccddeefX">>, 6)),
     ?_assertEqual(false, ?TEST_MODULE:is_valid_bin(extra, <<"00112233">>, 7)),
     ?_assertEqual(true, ?TEST_MODULE:is_valid_bin(miner, <<"aabbccddeeff">>, 6)),
     ?_assertEqual(true, ?TEST_MODULE:is_valid_bin(extra, <<"00112233">>, 4)),
     ?_assertEqual(true, ?TEST_MODULE:is_valid_bin(miner, <<"0F">>, 1)),
     ?_assertEqual(true, ?TEST_MODULE:is_valid_bin(extra, <<"01020304050607">>, 7))].

max(badarg) ->
    L = [0, -1, 1.0, not_int, 8],
    [?_assertException(error, badarg, ?TEST_MODULE:max(I)) || I <- L].

max_value(badarg) ->
    L = [atom, {foo, bar}, <<>>, []],
    [?_assertException(error, badarg, ?TEST_MODULE:max_value(I)) || I <- L];
max_value(valid) ->
    L = [?TEST_MODULE:new(12345), ?TEST_MODULE:new(extra, 0, 3),
         ?TEST_MODULE:new(miner, 1000, 4), ?TEST_MODULE:new(extra, 16#ff, 1)],
    [?_assertMatch(X when is_integer(X), ?TEST_MODULE:max_value(I)) || I <- L].

merge(badarg) ->
    L = [{0, 0}, {<<>>, []}, {1, 2},
         {?TEST_MODULE:new(extra, 0, 4), ?TEST_MODULE:new(extra, 0, 4)},
         {?TEST_MODULE:new(extra, 0, 4), ?TEST_MODULE:new(miner, 0, 3)},
         {?TEST_MODULE:new(miner, 1, 5), ?TEST_MODULE:new(miner, 1, 2)}],
    [?_assertException(error, badarg, ?TEST_MODULE:merge(P1, P2)) || {P1, P2} <- L];
merge(valid) ->
    L = [{?TEST_MODULE:new(extra, 0, 7),
          ?TEST_MODULE:new(miner, 0, 1),
          0},
         %% 01 00 00 00 00 | 00 00 00 (little) -> 00 00 00 00 00 00 00 01 (big)
         {?TEST_MODULE:new(extra, 0, 3),
          ?TEST_MODULE:new(miner, 1, 5),
          16#0000000000000001},
         %% 01 00 | 00 00 00 00 00 00 (little) -> 00 00 00 00 00 00 00 01 (big)
         {?TEST_MODULE:new(miner, 1, 2),
          ?TEST_MODULE:new(extra, 0, 6),
          16#0000000000000001},
         %% 00 00 00 00 00 00 | 01 00 (little) -> 00 01 00 00 00 00 00 00 (big)
         {?TEST_MODULE:new(extra, 1, 2),
          ?TEST_MODULE:new(miner, 0, 6),
          16#0001000000000000},
         %% d0 c0 b0 a0 | 40 30 20 10 (little) -> 10 20 30 40 a0 b0 c0 d0 (big)
         {?TEST_MODULE:new(miner, 16#a0b0c0d0, 4),
          ?TEST_MODULE:new(extra, 16#10203040, 4),
          16#10203040a0b0c0d0}],
    [?_assertEqual(R, ?TEST_MODULE:value(?TEST_MODULE:merge(P1, P2))) || {P1, P2, R} <- L].

split(badarg) ->
    L = [{atom, <<>>}, {foo, bar}, {123, 456}],
    [?_assertException(error, badarg, ?TEST_MODULE:split(S, N)) || {S, N} <- L];
split(valid) ->
    L = [{{extra, 4}, ?TEST_MODULE:new(0),
          {?TEST_MODULE:new(extra, 0, 4),
           ?TEST_MODULE:new(miner, 0, 4)}},
         {{miner, 2}, ?TEST_MODULE:new(1),
          {?TEST_MODULE:new(extra, 0, 6),
           ?TEST_MODULE:new(miner, 1, 2)}},
         {{extra, 6}, ?TEST_MODULE:new(1),
          {?TEST_MODULE:new(extra, 0, 6),
           ?TEST_MODULE:new(miner, 1, 2)}},
         {{miner, 4}, ?TEST_MODULE:new(16#10203040a0b0c0d0),
          {?TEST_MODULE:new(extra, 16#10203040, 4),
           ?TEST_MODULE:new(miner, 16#a0b0c0d0, 4)}}],
    [?_assertEqual(R, ?TEST_MODULE:split(S, N)) || {S, N, R} <- L].

update(badarg) ->
    L = [{<<>>, foo}, {[1, 2], 100.0}, {{foo, bar}, "baz"},
         {16#ff + 1, ?TEST_MODULE:new(miner, 16#ff, 1)},
         {16#ffff12345, ?TEST_MODULE:new(extra, 0, 2)}],
    [?_assertException(error, badarg, ?TEST_MODULE:update(V, N)) || {V, N} <- L];
update(valid) ->
    [?_assertEqual(
        16#ff, ?TEST_MODULE:value(?TEST_MODULE:update(16#ff, ?TEST_MODULE:new(extra, 0, 1)))),
     ?_assertEqual(
        16#ff, ?TEST_MODULE:value(?TEST_MODULE:update(16#ff, ?TEST_MODULE:new(miner, 16#ff, 1)))),
     ?_assertEqual(
        0, ?TEST_MODULE:value(?TEST_MODULE:update(0, ?TEST_MODULE:new(extra, 100, 3)))),
     ?_assertEqual(
        1, ?TEST_MODULE:value(?TEST_MODULE:update(1, ?TEST_MODULE:new(miner, 16#ffffffffff, 5))))].

type(badarg) ->
    L = [{}, <<>>, atom, ?TEST_MODULE:new(999)],
    [?_assertException(error, badarg, ?TEST_MODULE:type(I)) || I <- L];
type(valid) ->
    [?_assertEqual(extra, ?TEST_MODULE:type(?TEST_MODULE:new(extra, 100, 4))),
     ?_assertEqual(miner, ?TEST_MODULE:type(?TEST_MODULE:new(miner, 999, 3)))].

value(badarg) ->
    L = [<<"not nonce">>, {1, 2, 3}, foo],
    [?_assertException(error, badarg, ?TEST_MODULE:type(I)) || I <- L];
value(valid) ->
    [?_assertEqual(999, ?TEST_MODULE:value(?TEST_MODULE:new(999))),
     ?_assertEqual(0, ?TEST_MODULE:value(?TEST_MODULE:new(0))),
     ?_assertEqual(12345, ?TEST_MODULE:value(?TEST_MODULE:new(extra, 12345, 3))),
     ?_assertEqual(90590500, ?TEST_MODULE:value(?TEST_MODULE:new(miner,90590500, 5)))].

nbytes(badarg) ->
    L = [atom, <<>>, {foo, bar}],
    [?_assertException(error, badarg, ?TEST_MODULE:nbytes(I)) || I <- L];
nbytes(valid) ->
    [?_assertEqual(8, ?TEST_MODULE:nbytes(?TEST_MODULE:new(123456))),
     ?_assertEqual(3, ?TEST_MODULE:nbytes(?TEST_MODULE:new(miner, 1000, 3))),
     ?_assertEqual(1, ?TEST_MODULE:nbytes(?TEST_MODULE:new(miner, 120, 1)))].

complement_nbytes(badarg) ->
    L = [xyz, [foo, bar], 10, <<"binary">>],
    [?_assertException(error, badarg, ?TEST_MODULE:complement_nbytes(I)) || I <- L];
complement_nbytes(valid) ->
    [?_assertEqual(0, ?TEST_MODULE:complement_nbytes(?TEST_MODULE:new(5324))),
     ?_assertEqual(7, ?TEST_MODULE:complement_nbytes(?TEST_MODULE:new(extra, 123, 1))),
     ?_assertEqual(1, ?TEST_MODULE:complement_nbytes(?TEST_MODULE:new(miner, 539932, 7)))].

