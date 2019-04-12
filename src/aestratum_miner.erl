-module(aestratum_miner).

-export([hash_data/1,
         generate/6,
         verify/6,
         verify_proof/5,
         get_target/2
        ]).

-export([config/7,
         instances/1,
         repeats/1
        ]).

-export_type([block_hash/0,
              block_version/0,
              target/0,
              config/0,
              exec/0,
              exec_group/0,
              extra_args/0,
              hex_enc_header/0,
              repeats/0,
              instance/0,
              instances/0,
              edge_bits/0,
              pow/0
             ]).

-type nonce()          :: aestratum_nonce:nonce().

-type data()           :: aeminer_pow_cuckoo:hashable().

-type block_hash()     :: aeminer_pow_cuckoo:hash().

-type block_version()  :: pos_integer().

-type target()         :: aeminer_pow:int_target().

-type exec()           :: aeminer_pow_cuckoo:exec().

-type exec_group()     :: aeminer_pow_cuckoo:exec_group().

-type extra_args()     :: aeminer_pow_cuckoo:extra_args().

-type hex_enc_header() :: aeminer_pow_cuckoo:hex_enc_header().

-type repeats()        :: aeminer_pow_cuckoo:repeats().

-type instance()       :: aeminer_pow_cuckoo:instance().

-type instances()      :: aeminer_pow_cuckoo:instances().

-type edge_bits()      :: aeminer_pow_cuckoo:edge_bits().

-type pow()            :: aeminer_pow_cuckoo:solution().

-opaque config()       :: aeminer_pow_cuckoo:config().

-spec hash_data(data()) -> block_hash().
hash_data(Data) ->
    aeminer_pow_cuckoo:hash_data(Data).

-spec generate(block_hash(), block_version(), target(), nonce(),
               instance(), config()) ->
    {ok, {nonce(), pow()}} | {error, no_solution | {runtime, term()}}.
generate(BlockHash, _BlockVersion, Target, Nonce, Instance, Config) ->
    BlockHash1 = to_bin(BlockHash),
    Nonce1 = aestratum_nonce:value(Nonce),
    Target1 = aeminer_pow:integer_to_scientific(Target),
    aeminer_pow_cuckoo:generate_from_hash(BlockHash1, Target1, Nonce1, Config, Instance).

-spec verify(block_hash(), block_version(), nonce(), pow(), target(), edge_bits()) ->
    boolean().
verify(BlockHash, _BlockVersion, Nonce, Pow, Target, EdgeBits) ->
    Nonce1 = aestratum_nonce:value(Nonce),
    Target1 = aeminer_pow:integer_to_scientific(Target),
    aeminer_pow_cuckoo:verify(BlockHash, Nonce1, Pow, Target1, EdgeBits).

-spec verify_proof(block_hash(), block_version(), nonce(), pow(), edge_bits()) ->
    boolean().
verify_proof(BlockHash, _BlockVersion, Nonce, Pow, EdgeBits) ->
    Nonce1 = aestratum_nonce:value(Nonce),
    aeminer_pow_cuckoo:verify_proof(BlockHash, Nonce1, Pow, EdgeBits).

-spec get_target(pow(), edge_bits()) -> target().
get_target(Pow, EdgeBits) ->
    aeminer_pow_cuckoo:get_target(Pow, EdgeBits).

-spec config(exec(), exec_group(), extra_args(), hex_enc_header(), repeats(),
             edge_bits(), instances()) -> config().
config(Exec, ExecGroup, ExtraArgs, HexEncHdr, Repeats, EdgeBits, Instances) ->
    aeminer_pow_cuckoo:config(
      Exec, ExecGroup, ExtraArgs, HexEncHdr, Repeats, EdgeBits, Instances).

-spec instances(config()) -> instances().
instances(Config) ->
    aeminer_pow_cuckoo:addressed_instances(Config).

-spec repeats(config()) -> repeats().
repeats(Config) ->
    aeminer_pow_cuckoo:repeats(Config).

to_bin(S) ->
    to_bin(binary_to_list(S), []).

to_bin([], Acc) ->
    list_to_binary(lists:reverse(Acc));
to_bin([X, Y | T], Acc) ->
    {ok, [V], []} = io_lib:fread("~16u", [X, Y]),
    to_bin(T, [V | Acc]).

