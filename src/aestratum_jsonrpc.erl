-module(aestratum_jsonrpc).

-export([decode/1, decode/2,
         encode/1, encode/2,
         validate_rsp/2, validate_rsp/3,
         next_id/1, next_id/2,
         to_id/1, to_id/2
        ]).

-define(ID_MIN, 0).
-define(ID_MAX, 16#ffffffff).

-define(HOST_MAX_SIZE, 16#ff).

-define(PORT_MIN, 1).
-define(PORT_MAX, 16#ffff).

-define(USER_MAX_SIZE, 64).

-define(USER_AGENT_MAX_SIZE, 64).

-define(SESSION_ID_SIZE, 16).

-define(PASSWORD_SIZE, 64).

-define(TARGET_SIZE, 64).

-define(JOB_ID_SIZE, 16).

-define(BLOCK_VERSION_MIN, 1).
-define(BLOCK_VERSION_MAX, 16#ffffffff).

-define(BLOCK_HASH_SIZE, 64).

%% In seconds.
-define(WAIT_TIME_MIN, 0).
-define(WAIT_TIME_MAX, 60 * 60).

%% Size as hex encoded string.
-define(NONCE_SIZE, 16).

-define(POW_SIZE, 42).
-define(POW_NUMBER_MIN, 0).
-define(POW_NUMBER_MAX, 16#ffffffff).

-define(ERROR_MSG_MAX_SIZE, 16#ff).

-define(ERROR_DATA_MAX_SIZE, 16#1ff).

-type raw_msg()         :: binary().

-type req()             :: configure_req()
                         | subscribe_req()
                         | authorize_req()
                         | submit_req()
                         | reconnect_req().

-type ntf()             :: set_target_ntf()
                         | notify_ntf().

-type raw_rsp()         :: raw_result_rsp()
                         | raw_error_rsp().

-type rsp()             :: configure_rsp()
                         | subscribe_rsp()
                         | authorize_rsp()
                         | submit_rsp().

-type configure_req()   :: #{type          => req,
                             method        => configure,
                             id            => id(),
                             params        => []}.

-type subscribe_req()   :: #{type          => req,
                             method        => subscribe,
                             id            => id(),
                             user_agent    => user_agent(),
                             session_id    => session_id(),
                             host          => host(),
                             port          => integer_port()}.

-type authorize_req()   :: #{type          => req,
                             method        => authorize,
                             id            => id(),
                             user          => user(),
                             password      => password()}.

-type submit_req()      :: #{type          => req,
                             method        => submit,
                             id            => id(),
                             user          => user(),
                             job_id        => job_id(),
                             miner_nonce   => miner_nonce(),
                             pow           => pow()}.

-type reconnect_req()   :: #{type          => req,
                             method        => reconnect,
                             id            => id(),
                             host          => host(),
                             port          => maybe_null_port(),
                             wait_time     => wait_time()}.

-type set_target_ntf()  :: #{type          => ntf,
                             method        => set_target,
                             target        => target()}.

-type notify_ntf()      :: #{type          => ntf,
                             method        => notify,
                             job_id        => job_id(),
                             block_version => block_version(),
                             block_hash    => block_hash(),
                             empty_queue   => empty_queue()}.

-type configure_rsp()   :: #{type          => rsp,
                             method        => configure,
                             id            => id(),
                             result        => []}.

-type subscribe_rsp()   :: #{type          => rsp,
                             method        => subscribe,
                             id            => id(),
                             result        => nonempty_improper_list(
                                                session_id(), extra_nonce())}.

-type authorize_rsp()   :: #{type          => rsp,
                             method        => authorize,
                             id            => id(),
                             result        => boolean()}.

-type submit_rsp()      :: #{type          => rsp,
                             method        => submit,
                             id            => id(),
                             result        => boolean()}.

-type raw_result_rsp()  :: #{type          => rsp,
                             id            => id(),
                             result        => term()}.

-type raw_error_rsp()   :: #{type          => rsp,
                             id            => id() | null,
                             error         => term()}.

%% If there was an error in detecting the id in the Request object (e.g. Parse
%% error/Invalid Request), it MUST be Null.
-type error_dec_rsp()   :: #{type          => rsp,
                             method        => rsp_method(),
                             id            => id() | null,
                             reason        => error_reason(),
                             msg           => error_msg(),
                             data          => error_data()}.

%% Error response to be encoded. Id is allowed to be null since the request
%% (due to which this response is constructed) didn't have to have the Id
%% specified (or there was another error so the Id is unknown). We still try
%% to send a response to a request without Id.
-type error_enc_rsp()   :: #{type          => rsp,
                             method        => rsp_method(),
                             id            => id() | null,
                             reason        => error_reason(),
                             data          => error_data()}.

-type id()              :: ?ID_MIN..?ID_MAX.

-type user_agent()      :: binary().

-type session_id()      :: binary()
                         | null.

-type host()            :: binary()
                         | null.

-type integer_port()    :: ?PORT_MIN..?PORT_MAX.

-type maybe_null_port() :: integer_port()
                         | null.

-type user()            :: binary().

-type password()        :: binary().
                %% TODO: | null

-type job_id()          :: binary().

-type block_version()   :: ?BLOCK_VERSION_MIN..?BLOCK_VERSION_MAX.

-type block_hash()      :: binary().

-type miner_nonce()     :: binary().

-type extra_nonce()     :: binary().

-type pow()             :: [?POW_NUMBER_MIN..?POW_NUMBER_MAX].

-type target()          :: binary().

-type empty_queue()     :: boolean().

-type wait_time()       :: ?WAIT_TIME_MIN..?WAIT_TIME_MAX
                         | null.

-type rsp_method()      :: configure
                         | subscribe
                         | authorize
                         | submit
                         | undefined.

-type error_reason()    :: jsonrpc_reason()
                         | stratum_reason().

-type jsonrpc_reason()  :: parse_error
                         | invalid_msg
                         | invalid_method
                         | invalid_param
                         | internal_error.

-type stratum_reason()  :: unknown_error
                         | job_not_found
                         | duplicate_share
                         | low_difficulty_share
                         | unauthorized_worker
                         | not_subscribed.

-type error_msg()       :: binary()
                         | null.

-type error_data()      :: term()
                         | null.

-type reason()          :: parse_error
                         | {invalid_msg, maybe_id()}
                         | {invalid_method, maybe_id()}
                         | {invalid_param, param(), maybe_id()}
                         | {internal_error, maybe_id()}.

-type param()           :: atom().

-type maybe_id()        :: id()
                         | null
                         | undefined.

-type opts()            :: map().

-define(JSONRPC_VERSION, <<"2.0">>).

-define(ERROR_LOG(Fmt, Args), error_logger:error_msg(Fmt, Args)).

%% API.

-spec decode(raw_msg()) ->
    {ok, req() | ntf() | raw_rsp()} | {error, reason()}.
decode(RawMsg) when is_binary(RawMsg) ->
    decode(RawMsg, #{}).

-spec decode(raw_msg(), opts()) ->
    {ok, req() | ntf() | raw_rsp()} | {error, reason()}.
decode(RawMsg, Opts) when is_binary(RawMsg) and is_map(Opts) ->
    %% raw_msg -> msg -> map
    Data0 = #{op => decode, raw_msg => RawMsg},
    case raw_msg_to_msg(Data0, Opts) of
        {ok, Data} ->
            run([fun check_version/2,
                 fun msg_to_map/2], Data, Opts);
        {error, Rsn} ->
            decode_error(Rsn, Data0, Opts)
    end.

-spec encode(req() | ntf() | rsp() | error_enc_rsp()) ->
    {ok, raw_msg()} | {error, reason()}.
encode(Map) when is_map(Map) ->
    encode(Map, #{}).

-spec encode(req() | ntf() | rsp() | error_enc_rsp(), opts()) ->
    {ok, raw_msg()} | {error, reason()}.
encode(Map, Opts) when is_map(Map) and is_map(Opts) ->
    %% map -> msg -> raw_msg
    run([fun map_to_msg/2,
         fun msg_to_raw_msg/2], #{op => encode, map => Map}, Opts).

-spec validate_rsp(rsp_method(), raw_rsp()) ->
    {ok, rsp() | error_dec_rsp()} | {error, reason()}.
validate_rsp(Method, Rsp) ->
    validate_rsp(Method, Rsp, #{}).

-spec validate_rsp(rsp_method(), raw_rsp(), opts()) ->
    {ok, rsp() | error_dec_rsp()} | {error, reason()}.
validate_rsp(Method, #{result := Result} = Rsp, Opts) ->
    try
        ok = check_result(Method, Result, Opts),
        {ok, Rsp#{method => Method}}
    catch
        throw:{validation_error, Rsn} ->
            validation_error(Rsn, #{op => validate_rsp, map => Rsp}, Opts)
    end;
validate_rsp(Method, #{error := Error} = Rsp, Opts) ->
    try
        ok = check_error(Error, Opts),
        [Code, Msg, Data] = Error,
        %% replace error with reason, msg, data
        Rsp1 = maps:without([error], Rsp),
        {ok, Rsp1#{method => Method, reason => error_code_to_reason(Code),
                   msg => Msg, data => Data}}
    catch
        throw:{validation_error, Rsn} ->
            validation_error(Rsn, #{op => validate_rsp, map => Rsp}, Opts)
    end.

-spec next_id(id()) -> id().
next_id(Id) when is_integer(Id) ->
    next_id(Id, #{}).

%% The id_min can be any number non negative number smaller than id_max.
%% NOTE: The id_max must be a number which has in base 2 all bits set to 1.
%% For example, the id_max can be: 16#f, 16#ff, 16#ffffffff. The id_max,
%% for example, cannot be: 16#abc, 16#ff0.
-spec next_id(id(), opts()) -> id().
next_id(Id, Opts) when is_integer(Id) ->
    Min = maps:get(id_min, Opts, ?ID_MIN),
    Max = maps:get(id_max, Opts, ?ID_MAX),
    case ((Id + 1) band Max) of
        0 -> Min;
        N -> N
    end.

-spec to_id(term()) -> id() | null.
to_id(Id) ->
    to_id(Id, #{}).

-spec to_id(term(), opts()) -> id() | null.
to_id(Id, Opts) when is_integer(Id) ->
    Min = maps:get(id_min, Opts, ?ID_MIN),
    Max = maps:get(id_max, Opts, ?ID_MAX),
    case is_id(Id, Min, Max) of
        true  -> Id;
        false -> null
    end;
to_id(_Id, _Opts) ->
    null.

%% Internal functions.

run(Funs, Data0, Opts) ->
    try
        {ok, lists:foldl(fun(Fun, Data) -> Fun(Data, Opts) end, Data0, Funs)}
    catch
        throw:{validation_error, Rsn} ->
            validation_error(Rsn, Data0, Opts);
        throw:{encode_error, Rsn} ->
            encode_error(Rsn, Data0, Opts);
        error:Rsn ->
            ST = erlang:get_stacktrace(),
            internal_error(Rsn, ST, Data0, Opts)
    end.

validation_error(Rsn, #{op := decode} = Data, Opts) ->
    validation_erorr1(Rsn, id_from_msg(Data, Opts));
validation_error(Rsn, #{op := Op} = Data, Opts) when
      (Op =:= encode) or (Op =:= validate_rsp) ->
    validation_erorr1(Rsn, id_from_map(Data, Opts)).

validation_erorr1(invalid_msg, Id) ->
    {error, {invalid_msg, Id}};
validation_erorr1({field, Field}, Id) when
      (Field =:= jsonrpc) or (Field =:= id) ->
    {error, {invalid_msg, Id}};
validation_erorr1({field, method}, Id) ->
    {error, {invalid_method, Id}};
validation_erorr1({param, Param}, Id) ->
    {error, {invalid_param, Param, Id}}.

decode_error(Rsn, #{op := decode, raw_msg := RawMsg}, _Opts) ->
    ?ERROR_LOG("Decode error, reason: ~p, message: ~p", [Rsn, RawMsg]),
    {error, parse_error}.

encode_error(Rsn, #{op := encode, map := Map}, _Opts) ->
    ?ERROR_LOG("Encode error, reason: ~p, map: ~p", [Rsn, Map]),
    {error, parse_error}.

internal_error(Rsn, ST, #{op := decode, raw_msg := RawMsg} = Data, Opts) ->
    ?ERROR_LOG("Internal error, reason: ~p, message: ~p, stacktrace: ~9999p",
               [Rsn, RawMsg, ST]),
    {error, {internal_error, id_from_msg(Data, Opts)}};
internal_error(Rsn, ST, #{op := encode, map := Map} = Data, Opts) ->
    ?ERROR_LOG("Internal error, reason: ~p, map: ~p, stacktrace: ~9999p",
               [Rsn, Map, ST]),
    {error, {internal_error, id_from_map(Data, Opts)}}.

id_from_msg(#{msg := #{<<"id">> := Id}}, Opts) when is_integer(Id) ->
    Min = maps:get(id_min, Opts, ?ID_MIN),
    Max = maps:get(id_max, Opts, ?ID_MAX),
    case is_id(Id, Min, Max) of
        true -> Id;
        false -> undefined
    end;
id_from_msg(#{msg := #{<<"id">> := null}}, _Opts) ->
    null;
id_from_msg(_Other, _Opts) ->
    undefined.

id_from_map(#{map := #{id := Id}}, Opts) when is_integer(Id) ->
    Min = maps:get(id_min, Opts, ?ID_MIN),
    Max = maps:get(id_max, Opts, ?ID_MAX),
    case is_id(Id, Min, Max) of
        true -> Id;
        false -> undefined
    end;
id_from_map(#{map := #{id := null}}, _Opts) ->
    null;
id_from_map(_Other, _Opts) ->
    undefined.

raw_msg_to_msg(#{raw_msg := RawMsg} = Data, _Opts) ->
    try {ok, Data#{msg => jsx:decode(RawMsg, [return_maps])}}
    catch
        error:Rsn -> {error, Rsn}
    end.

msg_to_raw_msg(#{msg := Msg}, _Opts) ->
    try list_to_binary([jsx:encode(Msg), $\n])
    catch
        error:Rsn -> throw({encode_error, Rsn})
    end.

check_version(#{msg := #{<<"jsonrpc">> := ?JSONRPC_VERSION}} = Data, _Opts) ->
    Data;
check_version(#{msg := _Msg}, _Opts) ->
    validation_exception({field, jsonrpc}).

%% Client requests
msg_to_map(#{msg := #{<<"id">> := Id,
                      <<"method">> := <<"mining.configure">>,
                      <<"params">> := Params}}, Opts) ->
    ok = check_configure_req(Id, Params, Opts),
    #{type => req, method => configure, id => Id, params => Params};
msg_to_map(#{msg := #{<<"id">> := Id,
                      <<"method">> := <<"mining.subscribe">>,
                      <<"params">> := Params}}, Opts) ->
    ok = check_subscribe_req(Id, Params, Opts),
    [UserAgent, SessionId, Host, Port] = Params,
    #{type => req, method => subscribe, id => Id, user_agent => UserAgent,
      session_id => lowercase(SessionId), host => Host,
      port => Port};
msg_to_map(#{msg := #{<<"id">> := Id,
                      <<"method">> := <<"mining.authorize">>,
                      <<"params">> := Params}}, Opts) ->
    ok = check_authorize_req(Id, Params, Opts),
    [User, Password] = Params,
    #{type => req, method => authorize, id => Id, user => User,
      password => lowercase(Password)};
msg_to_map(#{msg := #{<<"id">> := Id,
                      <<"method">> := <<"mining.submit">>,
                      <<"params">> := Params}}, Opts) ->
    ok = check_submit_req(Id, Params, Opts),
    [User, JobId, MinerNonce, Pow] = Params,
    #{type => req, method => submit, id => Id, user => User,
      job_id => lowercase(JobId), miner_nonce => lowercase(MinerNonce),
      pow => Pow};
%% Server requests
msg_to_map(#{msg := #{<<"id">> := Id,
                      <<"method">> := <<"client.reconnect">>,
                      <<"params">> := Params}}, Opts) ->
    ok = check_reconnect_req(Id, Params, Opts),
    case Params of
        [] ->
            #{type => req, method => reconnect, id => Id, host => null,
              port => null, wait_time => 0};
        [Host, Port, WaitTime] ->
            #{type => req, method => reconnect, id => Id, host => Host,
              port => Port, wait_time => WaitTime}
    end;
%% Server notifications
msg_to_map(#{msg := #{<<"id">> := Id,
                      <<"method">> := <<"mining.set_target">>,
                      <<"params">> := Params}}, Opts) ->
    ok = check_set_target_ntf(Id, Params, Opts),
    [Target] = Params,
    #{type => ntf, method => set_target, id => null,
      target => lowercase(Target)};
msg_to_map(#{msg := #{<<"id">> := Id,
                      <<"method">> := <<"mining.notify">>,
                      <<"params">> := Params}}, Opts) ->
    ok = check_notify_ntf(Id, Params, Opts),
    [JobId, BlockVersion, BlockHash, EmptyQueue] = Params,
    #{type => ntf, method => notify, id => null, job_id => lowercase(JobId),
      block_version => BlockVersion, block_hash => lowercase(BlockHash),
      empty_queue => EmptyQueue};
%% Responses
msg_to_map(#{msg := #{<<"id">> := Id,
                      <<"result">> := Result,
                      <<"error">> := null}}, Opts) when Result =/= null ->
    ok = check_id(int, Id, Opts),
    %% Result is not checked here, the check is done in
    %% validate_rsp_params/2. We don't have info about what
    %% response params are expected here. There is no info
    %% on what kind of response this is.
    #{type => rsp, id => Id, result => Result};
msg_to_map(#{msg := #{<<"id">> := Id,
                      <<"result">> := null,
                      <<"error">> := Error}}, Opts) when Error =/= null ->
    ok = check_id(allow_null, Id, Opts),
    %% Error is not checked here, the check is done in
    %% validate_rsp_params/2. It could be done here though,
    %% but let's follow the behaviour of how it's done with
    %% the result above.
    #{type => rsp, id => Id, error => Error};
%% Msg validation errors
msg_to_map(#{msg := #{<<"id">> := _Id,
                      <<"method">> := _Method,
                      <<"params">> := Params}}, _Opts) when is_list(Params) ->
    validation_exception({field, method});
msg_to_map(_Data, _Opts) ->
    validation_exception(invalid_msg).

map_to_msg(#{map := #{type := req, method := configure, id := Id,
                      params := Params}} = Data, Opts) ->
    ok = check_configure_req(Id, Params, Opts),
    to_req_msg(<<"mining.configure">>, Id, Params, Data);
map_to_msg(#{map := #{type := req, method := subscribe, id := Id,
                      user_agent := UserAgent, session_id := SessionId,
                      host := Host, port := Port}} = Data, Opts) ->
    Params = [UserAgent, SessionId, Host, Port],
    ok = check_subscribe_req(Id, Params, Opts),
    to_req_msg(<<"mining.subscribe">>, Id, Params, Data);
map_to_msg(#{map := #{type := req, method := authorize, id := Id,
                      user := User, password := Password}} = Data, Opts) ->
    Params = [User, Password],
    ok = check_authorize_req(Id, Params, Opts),
    to_req_msg(<<"mining.authorize">>, Id, Params, Data);
map_to_msg(#{map := #{type := req, method := submit, id := Id,
                      user := User, job_id := JobId, miner_nonce := MinerNonce,
                      pow := Pow}} = Data, Opts) ->
    Params = [User, JobId, MinerNonce, Pow],
    ok = check_submit_req(Id, Params, Opts),
    to_req_msg(<<"mining.submit">>, Id, Params, Data);
map_to_msg(#{map := #{type := req, method := reconnect, id := Id,
                      host := Host, port := Port,
                      wait_time := WaitTime}} = Data, Opts) ->
    Params =
        case [Host, Port, WaitTime] of
            [null, null, 0] -> [];
            [_Host1, _Port1, _WaitTime1] = Params1 -> Params1
        end,
    ok = check_reconnect_req(Id, Params, Opts),
    to_req_msg(<<"client.reconnect">>, Id, Params, Data);
map_to_msg(#{map := #{type := ntf, method := set_target,
                      target := Target}} = Data, Opts) ->
    ok = check_set_target_ntf(null, [Target], Opts),
    to_ntf_msg(<<"mining.set_target">>, [Target], Data);
map_to_msg(#{map := #{type := ntf, method := notify, job_id := JobId,
                      block_version := BlockVersion, block_hash := BlockHash,
                      empty_queue := EmptyQueue}} = Data, Opts) ->
    Params = [JobId, BlockVersion, BlockHash, EmptyQueue],
    ok = check_notify_ntf(null, Params, Opts),
    to_ntf_msg(<<"mining.notify">>, Params, Data);
map_to_msg(#{map := #{type := rsp, method := Method, id := Id,
                      result := Result}} = Data, Opts) ->
    ok = check_id(int, Id, Opts),
    ok = check_result(Method, Result, Opts),
    to_result_rsp_msg(Id, Result, Data);
map_to_msg(#{map := #{type := rsp, id := Id, reason := Rsn,
                      data := ErrorData}} = Data, Opts) ->
    ok = check_id(allow_null, Id, Opts),
    ok = check_error_data(ErrorData, Opts),
    ErrorParams = reason_to_error_params(Rsn, ErrorData),
    to_error_rsp_msg(Id, ErrorParams, Data);
map_to_msg(_Other, _Opts) ->
    validation_exception(invalid_msg).

to_req_msg(Method, Id, Params, Data) ->
    Data#{msg => #{<<"jsonrpc">> => ?JSONRPC_VERSION, <<"method">> => Method,
                   <<"id">> => Id, <<"params">> => Params}}.

to_ntf_msg(Method, Params, Data) ->
    Data#{msg => #{<<"jsonrpc">> => ?JSONRPC_VERSION, <<"method">> => Method,
                   <<"id">> => null, <<"params">> => Params}}.

to_result_rsp_msg(Id, Result, Data) ->
    Data#{msg => #{<<"jsonrpc">> => ?JSONRPC_VERSION, <<"id">> => Id,
                   <<"result">> => Result, <<"error">> => null}}.

to_error_rsp_msg(Id, Error, Data) ->
    Data#{msg => #{<<"jsonrpc">> => ?JSONRPC_VERSION, <<"id">> => Id,
                   <<"result">> => null, <<"error">> => Error}}.

check_configure_req(Id, [], Opts) ->
    ok = check_id(int, Id, Opts);
check_configure_req(_Id, _Params, _Opts) ->
    validation_exception({param, configure_params}).

check_subscribe_req(Id, [UserAgent, SessionId, Host, Port], Opts) ->
    ok = check_id(int, Id, Opts),
    ok = check_user_agent(UserAgent, Opts),
    ok = check_session_id(SessionId, Opts),
    ok = check_host(Host, Opts),
    ok = check_port(int, Port, Opts);
check_subscribe_req(_Id, _Params, _Opts) ->
    validation_exception({param, subscribe_params}).

check_authorize_req(Id, [User, Password], Opts) ->
    ok = check_id(int, Id, Opts),
    ok = check_user(User, Opts),
    ok = check_password(Password, Opts);
check_authorize_req(_Id, _Params, _Opts) ->
    validation_exception({param, authorize_params}).

check_submit_req(Id, [User, JobId, MinerNonce, Pow], Opts) ->
    ok = check_id(int, Id, Opts),
    ok = check_user(User, Opts),
    ok = check_job_id(JobId, Opts),
    ok = check_miner_nonce(MinerNonce, Opts),
    ok = check_pow(Pow, Opts);
check_submit_req(_Id, _Params, _Opts) ->
    validation_exception({param, submit_params}).

check_reconnect_req(Id, [Host, Port, WaitTime], Opts) ->
    ok = check_id(int, Id, Opts),
    ok = check_host(Host, Opts),
    ok = check_port(allow_null, Port, Opts),
    ok = check_wait_time(WaitTime, Opts);
check_reconnect_req(Id, [], Opts) ->
    ok = check_id(int, Id, Opts);
check_reconnect_req(_Id, _Params, _Opts) ->
    validation_exception({param, reconnect_params}).

check_set_target_ntf(Id, [Target], Opts) ->
    ok = check_id(null, Id, Opts),
    ok = check_target(Target, Opts);
check_set_target_ntf(_Id, _Params, _Opts) ->
    validation_exception({param, set_target_params}).

check_notify_ntf(Id, [JobId, BlockVersion, BlockHash, EmptyQueue], Opts) ->
    ok = check_id(null, Id, Opts),
    ok = check_job_id(JobId, Opts),
    ok = check_block_version(BlockVersion, Opts),
    ok = check_block_hash(BlockHash, Opts),
    ok = check_empty_queue(EmptyQueue, Opts);
check_notify_ntf(_Id, _Params, _Opts) ->
    validation_exception({param, notify_params}).

check_id(null, null, _Opts) ->
    ok;
check_id(int, Id, Opts) when is_integer(Id) ->
    Min = maps:get(id_min, Opts, ?ID_MIN),
    Max = maps:get(id_max, Opts, ?ID_MAX),
    case is_id(Id, Min, Max) of
        true  -> ok;
        false -> validation_exception({field, id})
    end;
check_id(allow_null, null, _Opts) ->
    ok;
check_id(allow_null, Id, Opts) ->
    check_id(int, Id, Opts);
check_id(_Type, _Id, _Opts) ->
    validation_exception({field, id}).

is_id(Id, Min, Max) when (Id >= Min) and (Id =< Max) ->
    true;
is_id(_Id, _Min, _Max) ->
    false.

check_user_agent(UserAgent, Opts) when is_binary(UserAgent) ->
    MaxSize = maps:get(user_agent_max_size, Opts, ?USER_AGENT_MAX_SIZE),
    case is_user_agent(UserAgent, MaxSize) of
        true  -> ok;
        false -> validation_exception({param, user_agent})
    end;
check_user_agent(_UserAgent, _Opts) ->
    validation_exception({param, user_agent}).

is_user_agent(UserAgent, MaxSize) ->
    case byte_size(UserAgent) of
        N when (N > 0) and (N =< MaxSize) ->
            case is_valid_string(UserAgent) of
                true ->
                    case binary:split(UserAgent, <<"/">>) of
                        [Client, Version] when
                              (Client =/= <<>>) and (Version =/= <<>>) ->
                            true;
                        _Other ->
                            false
                    end;
                false ->
                    false
            end;
        _Other ->
            false
    end.

check_session_id(null, _Opts) ->
    ok;
check_session_id(SessionId, Opts) when is_binary(SessionId) ->
    Size = maps:get(session_id_size, Opts, ?SESSION_ID_SIZE),
    case is_session_id(SessionId, Size) of
        true  -> ok;
        false -> validation_exception({param, session_id})
    end;
check_session_id(_SessionId, _Opts) ->
    validation_exception({param, session_id}).

is_session_id(SessionId, Size) when byte_size(SessionId) =:= Size ->
    is_hex(SessionId);
is_session_id(_SessionId, _Size) ->
    false.

check_host(null, _Opts) ->
    ok;
check_host(Host, Opts) when is_binary(Host) ->
    MaxSize = maps:get(host_max_size, Opts, ?HOST_MAX_SIZE),
    case is_host(Host, MaxSize) of
        true  -> ok;
        false -> validation_exception({param, host})
    end;
check_host(_Host, _Opts) ->
    validation_exception({param, host}).

is_host(Host, MaxSize) ->
    case byte_size(Host) of
        N when (N > 0) and (N =< MaxSize) ->
            is_valid_string(Host);
        _Other ->
            false
    end.

check_port(allow_null, null, _Opts) ->
    ok;
check_port(allow_null, Port, _Opts) ->
    check_port1(Port, _Opts);
check_port(int, Port, _Opts) ->
    check_port1(Port, _Opts).

check_port1(Port, Opts) when is_integer(Port) ->
    Min = maps:get(port_min, Opts, ?PORT_MIN),
    Max = maps:get(port_max, Opts, ?PORT_MAX),
    case is_port(Port, Min, Max) of
        true  -> ok;
        false -> validation_exception({param, port})
    end;
check_port1(_Port, _Opts) ->
    validation_exception({param, port}).

is_port(Port, Min, Max) when (Port > Min) and (Port =< Max) ->
    true;
is_port(_Port, _Min, _Max) ->
    false.

%% User can either have user_max_size or user_size (for fixed lenght size). The
%% default is user_max_size.
check_user(User, Opts) when is_binary(User) ->
    %% TODO: user_size
    MaxSize = maps:get(user_max_size, Opts, ?USER_MAX_SIZE),
    case is_user(User, MaxSize) of
        true  -> ok;
        false -> validation_exception({param, user})
    end;
check_user(_User, _Opts) ->
    validation_exception({param, user}).

is_user(User, MaxSize) ->
    case byte_size(User) of
        N when (N > 0) and (N =< MaxSize) ->
            is_valid_string(User);
        _Other ->
            false
    end.

check_password(Password, Opts) when is_binary(Password) ->
    Size = maps:get(password_size, Opts, ?PASSWORD_SIZE),
    case is_password(Password, Size) of
        true  -> ok;
        false -> validation_exception({param, password})
    end;
check_password(_Password, _Opts) ->
    validation_exception({param, password}).

is_password(Password, Size) when byte_size(Password) =:= Size ->
    is_hex(Password);
is_password(_Password, _Size) ->
    false.

check_target(Target, Opts) when is_binary(Target) ->
    Size = maps:get(target_size, Opts, ?TARGET_SIZE),
    case is_target(Target, Size) of
        true  -> ok;
        false -> validation_exception({param, target})
    end;
check_target(_Target, _Opts) ->
    validation_exception({param, target}).

is_target(Target, Size) when byte_size(Target) =:= Size ->
    is_hex(Target);
is_target(_Target, _Size) ->
    false.

check_job_id(JobId, Opts) when is_binary(JobId) ->
    Size = maps:get(job_id_size, Opts, ?JOB_ID_SIZE),
    case is_job_id(JobId, Size) of
        true  -> ok;
        false -> validation_exception({param, job_id})
    end;
check_job_id(_JobId, _Opts) ->
    validation_exception({param, job_id}).

is_job_id(JobId, Size) when byte_size(JobId) =:= Size ->
    is_hex(JobId);
is_job_id(_JobId, _Size) ->
    false.

check_block_version(BlockVersion, Opts) when is_integer(BlockVersion) ->
    Min = maps:get(block_version_min, Opts, ?BLOCK_VERSION_MIN),
    Max = maps:get(block_version_max, Opts, ?BLOCK_VERSION_MAX),
    case is_block_version(BlockVersion, Min, Max) of
        true  -> ok;
        false -> validation_exception({param, block_version})
    end;
check_block_version(_BlockVersion, _Opts) ->
    validation_exception({param, block_version}).

is_block_version(BlockVersion, Min, Max) when
      (BlockVersion >= Min) and (BlockVersion =< Max) ->
    true;
is_block_version(_BlockVersion, _Min, _Max) ->
    false.

check_block_hash(BlockHash, Opts) when is_binary(BlockHash) ->
    Size = maps:get(block_hash_size, Opts, ?BLOCK_HASH_SIZE),
    case is_block_hash(BlockHash, Size) of
        true  -> ok;
        false -> validation_exception({param, block_hash})
    end;
check_block_hash(_BlockHash, _Opts) ->
    validation_exception({param, block_hash}).

is_block_hash(BlockHash, Size) when byte_size(BlockHash) =:= Size ->
    is_hex(BlockHash);
is_block_hash(_BlockHash, _Size) ->
    false.

check_empty_queue(EmptyQueue, _Opts) when is_boolean(EmptyQueue) ->
    ok;
check_empty_queue(_EmptyQueue, _Opts) ->
    validation_exception({param, empty_queue}).

check_wait_time(WaitTime, Opts) when is_integer(WaitTime) ->
    Min = maps:get(wait_time_min, Opts, ?WAIT_TIME_MIN),
    Max = maps:get(wait_time_max, Opts, ?WAIT_TIME_MAX),
    case is_wait_time(WaitTime, Min, Max) of
        true  -> ok;
        false -> validation_exception({param, wait_time})
    end;
check_wait_time(_WaitTime, _Opts) ->
    validation_exception({param, wait_time}).

is_wait_time(WaitTime, Min, Max) when
      (WaitTime >= Min) and (WaitTime =< Max) ->
    true;
is_wait_time(_WaitTime, _Min, _Max) ->
    false.

check_miner_nonce(MinerNonce, Opts) when is_binary(MinerNonce) ->
    %% Nonce size is hex encoded integer, it must be an even number!
    NonceSize = maps:get(nonce_size, Opts, ?NONCE_SIZE),
    case is_part_nonce(MinerNonce, NonceSize) of
        true  -> ok;
        false -> validation_exception({param, miner_nonce})
    end;
check_miner_nonce(_MinerNonce, _Opts) ->
    validation_exception({param, miner_nonce}).

check_extra_nonce(ExtraNonce, Opts) when is_binary(ExtraNonce) ->
    %% Nonce size is hex encoded integer, it must be an even number!
    NonceSize = maps:get(nonce_size, Opts, ?NONCE_SIZE),
    case is_part_nonce(ExtraNonce, NonceSize) of
        true  -> ok;
        false -> validation_exception({param, extra_nonce})
    end;
check_extra_nonce(_ExtraNonce, _Opts) ->
    validation_exception({param, extra_nonce}).

is_part_nonce(PartNonce, NonceSize) ->
    case byte_size(PartNonce) of
        %% Miner nonce must have less bytes than the nonce.
        N when (N > 0) and (N < NonceSize) ->
            is_even(N) andalso is_hex(PartNonce);
        _Other ->
            false
    end;
is_part_nonce(_PartNonce, _NonceSize) ->
    false.

check_pow(Pow, Opts) when is_list(Pow) ->
    Size = maps:get(pow_size, Opts, ?POW_SIZE),
    PowNumberMin = maps:get(pow_number_min, Opts, ?POW_NUMBER_MIN),
    PowNumberMax = maps:get(pow_number_max, Opts, ?POW_NUMBER_MAX),
    case is_pow(Pow, Size, PowNumberMin, PowNumberMax) of
        true  -> ok;
        false -> validation_exception({param, pow})
    end;
check_pow(_Pow, _Opts) ->
    validation_exception({param, pow}).

is_pow(Pow, Size, PowNumberMin, PowNumberMax) when length(Pow) =:= Size ->
    lists:all(fun(N) when (N >= PowNumberMin) and (N =< PowNumberMax) ->
                      true;
                 (_N) ->
                      false
              end, Pow);
is_pow(_Pow, _Size, _PowNumberMin, _PowNumberMax) ->
    false.

%% Configure response: [] (no config params supported)
%% Subscribe response: [SessionId, ExtraNonce]
%% Authorize response: true | false
%% Submit response:    true | false
check_result(configure, [], _Opts) ->
    ok;
check_result(subscribe, [SessionId, ExtraNonce], Opts) ->
    ok = check_session_id(SessionId, Opts),
    ok = check_extra_nonce(ExtraNonce, Opts);
check_result(authorize, Result, _Opts) when is_boolean(Result) ->
    ok;
check_result(submit, Result, _Opts) when is_boolean(Result) ->
    ok;
check_result(configure, _Result, _Opts) ->
    validation_exception({param, configure_params});
check_result(subscribe, _Result, _Opts) ->
    validation_exception({param, subscribe_params});
check_result(authorize, _Result, _Opts) ->
    validation_exception({param, authorize_params});
check_result(submit, _Result, _Opts) ->
    validation_exception({param, submit_params}).

check_error([Code, Msg, Data], Opts) ->
    ok = check_error_code(Code),
    ok = check_error_msg(Msg, Opts),
    ok = check_error_data(Data, Opts);
check_error(_Error, _Opts) ->
    validation_exception({param, error_params}).

check_error_code(Code) ->
    _ = error_code_to_reason(Code),
    ok.

check_error_msg(Msg, Opts) when is_binary(Msg) ->
    MaxSize = maps:get(error_msg_max_size, Opts, ?ERROR_MSG_MAX_SIZE),
    case is_error_msg(Msg, MaxSize) of
        true  -> ok;
        false -> validation_exception({param, error_msg})
    end;
check_error_msg(_Msg, _Opts) ->
    validation_exception({param, error_msg}).

is_error_msg(Msg, MaxSize) ->
    case byte_size(Msg) of
        N when (N > 0) and (N =< MaxSize) ->
            true;
        _Other ->
            false
    end.

check_error_data(null, _Opts) ->
    ok;
check_error_data(Data, Opts) when is_binary(Data) ->
    MaxSize = maps:get(error_data_max_size, Opts, ?ERROR_DATA_MAX_SIZE),
    case is_error_data(Data, MaxSize) of
        true  -> ok;
        false -> validation_exception({param, error_data})
    end;
check_error_data(_Data, _Opts) ->
    validation_exception({param, error_data}).

is_error_data(Data, MaxSize) ->
    case byte_size(Data) of
        N when (N > 0) and (N =< MaxSize) ->
            true;
        _Other ->
            false
    end.

validation_exception(Rsn) ->
    throw({validation_error, Rsn}).

reason_to_error_params(parse_error, Data) ->
    [-32700, <<"Parse error">>, Data];
reason_to_error_params(invalid_msg, Data) ->
    [-32000, <<"Invalid request">>, Data];
reason_to_error_params(invalid_method, Data) ->
    [-32601, <<"Method not found">>, Data];
reason_to_error_params(invalid_param, Data)  ->
    [-32602, <<"Invalid params">>, Data];
reason_to_error_params(internal_error, Data) ->
    [-32603, <<"Internal error">>, Data];
reason_to_error_params(unknown_error, Data) ->
    [20, <<"Other/Unknown">>, Data];
reason_to_error_params(job_not_found, Data) ->
    [21, <<"Job not found">>, Data];
reason_to_error_params(duplicate_share, Data) ->
    [22, <<"Duplicate share">>, Data];
reason_to_error_params(low_difficulty_share, Data) ->
    [23, <<"Low difficulty share">>, Data];
reason_to_error_params(unauthorized_worker, Data) ->
    [24, <<"Unauthorized worker">>, Data];
reason_to_error_params(not_subscribed, Data) ->
    [25, <<"Not subscribed">>, Data];
reason_to_error_params(_Rsn, _Data) ->
    validation_exception({param, error_reason}).

error_code_to_reason(-32700) -> parse_error;
error_code_to_reason(-32000) -> invalid_msg;
error_code_to_reason(-32601) -> invalid_method;
error_code_to_reason(-32602) -> invalid_param;
error_code_to_reason(-32603) -> internal_error;
error_code_to_reason(20)     -> unknown_error;
error_code_to_reason(21)     -> job_not_found;
error_code_to_reason(22)     -> duplicate_share;
error_code_to_reason(23)     -> low_difficulty_share;
error_code_to_reason(24)     -> unauthorized_worker;
error_code_to_reason(25)     -> not_subscribed;
error_code_to_reason(_Code)  -> validation_exception({param, error_code}).

is_even(X) when X >= 0 ->
    (X band 1) =:= 0.

is_hex(Bin) when is_binary(Bin) ->
    lists:all(fun(Byte) when Byte >= $0, Byte =< $9 -> true;
                 (Byte) when Byte >= $a, Byte =< $f -> true;
                 (Byte) when Byte >= $A, Byte =< $F -> true;
                 (_Byte) -> false end, binary_to_list(Bin)).

is_valid_string(Bin) when is_binary(Bin) ->
    lists:all(fun(Byte) when Byte =:= $\s -> false;
                 (Byte) when Byte =:= $\n -> false;
                 (Byte) when Byte =:= $\t -> false;
                 (Byte) when Byte =:= $\v -> false;
                 (Byte) when Byte =:= $\f -> false;
                 (Byte) when Byte =:= $\r -> false;
                 (_Byte) -> true end, binary_to_list(Bin)).

lowercase(Bin) when is_binary(Bin) ->
    string:lowercase(Bin);
lowercase(Other) ->
    Other.

