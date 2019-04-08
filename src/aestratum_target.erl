-module(aestratum_target).

%% TODO: eunit

-export([recalculate/3,
         diff/2,
         max/0,
         to_hex/1,
         to_int/1
        ]).

-export_type([int_target/0,
              bin_target/0,
              solve_time/0,
              percent_change/0
             ]).

-include_lib("aeminer/include/aeminer.hrl").

-define(MAX_TARGET, ?HIGHEST_TARGET_INT).

-type int_target()     :: aeminer_pow:int_target().

-type bin_target()     :: aeminer_pow:bin_target().

-type prev_target()    :: {int_target(), solve_time()}.

-type solve_time()     :: pos_integer().

-type percent_change() :: float().

-spec recalculate([prev_target()], solve_time(), int_target()) -> int_target().
recalculate(PrevTargets, DesiredSolveTime, MaxTarget) when
      PrevTargets =/= [] ->
    N = length(PrevTargets),
    K = MaxTarget * (1 bsl 32),
    {SumKDivTargets, SumSolveTime} =
        lists:foldl(
          fun({Target, SolveTime}, {SumKDivTargets0, SumSolveTime0}) ->
                  {(K div Target) + SumKDivTargets0, SolveTime + SumSolveTime0}
          end, {0, 0}, PrevTargets),
    TemperedTST = (3 * N * DesiredSolveTime) div 4 + (2523 * SumSolveTime) div 10000,
    NewTarget = TemperedTST * K div (DesiredSolveTime * SumKDivTargets),
    min(MaxTarget, NewTarget);
recalculate([], _DesiredSolveTime, MaxTarget) ->
    MaxTarget.

-spec diff(int_target(), int_target()) ->
    {increase | decrease, percent_change()} | no_change.
diff(NewTarget, OldTarget) when NewTarget > OldTarget ->
    {increase, (NewTarget - OldTarget) / OldTarget * 100};
diff(NewTarget, OldTarget) when NewTarget < OldTarget ->
    {decrease, (OldTarget - NewTarget) / OldTarget * 100};
diff(Target, Target) ->
    no_change.

-spec max() -> int_target().
max() ->
    ?MAX_TARGET.

-spec to_hex(int_target()) -> bin_target().
to_hex(Target) ->
    iolist_to_binary(io_lib:format("~64.16.0b", [Target])).

-spec to_int(bin_target()) -> int_target().
to_int(Bin) ->
    binary_to_integer(Bin, 16).

