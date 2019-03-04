-module(aestratum_miner).

-export([generate/6,
         verify/6
        ]).

-export([config/7,
         instances/1,
         repeats/1
        ]).

-type block_hash()     :: aeminer_pow_cuckoo:hashable().

-type block_version()  :: pos_integer().

-type target()         :: aeminer_pow:int_target().

-type nonce()          :: aestratum_nonce:nonce().

-type config()         :: aeminer_pow_cuckoo:config().

-type exec()           :: aeminer_pow_cuckoo:exec().

-type exec_group()     :: aeminer_pow_cuckoo:exec_group().

-type extra_args()     :: aeminer_pow_cuckoo:extra_args().

-type hex_enc_header() :: aeminer_pow_cuckoo:hex_enc_header().

-type repeats()        :: aeminer_pow_cuckoo:repeats().

-type instance()       :: aeminer_pow_cuckoo:instance().

-type instances()      :: aeminer_pow_cuckoo:instances().

-type edge_bits()      :: aeminer_pow_cuckoo:edge_bits().

-type solution()       :: aeminer_pow_cuckoo:solution().

-spec generate(block_hash(), block_version(), target(), nonce(),
               instance(), config()) ->
    {ok, {nonce(), solution()}} | {error, no_solution | {runtime, term()}}.
generate(BlockHash, _BlockVersion, Target, Nonce, Instance, Config) ->
    Nonce1 = aestratum_nonce:value(Nonce),
    Target1 = aeminer_pow:integer_to_scientific(Target),
    aeminer_pow_cuckoo:generate(BlockHash, Target1, Nonce1, Config, Instance).

-spec verify(block_hash(), block_version(), nonce(), solution(),
             target(), edge_bits()) ->
    boolean().
verify(BlockHash, _BlockVersion, Nonce, Solution, Target, EdgeBits) ->
    Nonce1 = aestratum_nonce:value(Nonce),
    Target1 = aeminer_pow:integer_to_scientific(Target),
    aeminer_pow_cuckoo:verify(BlockHash, Nonce1, Solution, Target1, EdgeBits).

%% TODO: fix types in aeminer first
%%-spec config(exec(), exec_group(), extra_args(), hex_enc_header(), repeats(),
%%             edge_bits(), instances()) -> config().
config(Exec, ExecGroup, ExtraArgs, HexEncHdr, Repeats, EdgeBits, Instances) ->
    aeminer_pow_cuckoo:config(
      Exec, ExecGroup, ExtraArgs, HexEncHdr, Repeats,EdgeBits, Instances).

-spec instances(config()) -> instances().
instances(Config) ->
    aeminer_pow_cuckoo:addressed_instances(Config).

-spec repeats(config()) -> repeats().
repeats(Config) ->
    aeminer_pow_cuckoo:repeats(Config).

