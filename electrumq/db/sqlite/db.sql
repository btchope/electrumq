CREATE TABLE IF NOT EXISTS blocks(
    block_no INTEGER NOT NULL,    --块的编号--
    block_hash TEXT NOT NULL PRIMARY KEY,  --000000xxxxx--
    block_root TEXT NOT NULL,         --merktreeROOT--
    block_ver INTEGER NOT NULL,       --版本--
    block_bits INTEGER NOT NULL,      --难度--
    block_nonce INTEGER NOT NULL,     --随机数--
    block_time INTEGER NOT NULL,      --Unix的时间戳--
    block_prev TEXT,                  --上一个块的hash--
    is_main INTEGER NOT NULL   --是否是主链--
);

CREATE TABLE IF NOT EXISTS txs(
    tx_hash TEXT PRIMARY KEY,
    tx_ver INTEGER,  -- 交易版本 --
    tx_locktime INTEGER,    --生效时间--
    tx_time INTEGER,
    block_no INTEGER, -- block_no: 0 表示未认证
    source INTEGER  -- 是否由自己发出：0, 1 --
);

CREATE TABLE IF NOT EXISTS ins(
    tx_hash TEXT NOT NULL,  --交易hash --
    in_sn INTEGER NOT NULL, --第几个in--
    prev_tx_hash TEXT,      --上一个交易hash--
    prev_out_sn INTEGER,    --来源的第几个out--
    in_signature TEXT,      --入的签名--
    in_sequence INTEGER,    --入的序列--

    PRIMARY KEY (tx_hash, in_sn)
);

CREATE TABLE IF NOT EXISTS outs(
    tx_hash TEXT NOT NULL,
    out_sn INTEGER NOT NULL,  --out的第几个--
    out_script TEXT NOT NULL,
    out_value INTEGER NOT NULL,   --出的钱--
    out_status INTEGER NOT NULL,
    out_address TEXT,

    PRIMARY KEY (tx_hash, out_sn)
);

CREATE TABLE IF NOT EXISTS ins(
    tx_hash TEXT NOT NULL,
    in_sn INTEGER NOT NULL,
    prev_tx_hash TEXT,
    prev_out_sn INTEGER,
    in_signature TEXT,
    in_sequence INTEGER,

    PRIMARY KEY (tx_hash, in_sn)
);

CREATE TABLE IF NOT EXISTS addresses_txs(
    address TEXT NOT NULL,
    tx_hash TEXT NOT NULL,

    PRIMARY KEY (address, tx_hash)
);


