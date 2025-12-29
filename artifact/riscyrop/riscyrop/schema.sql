CREATE TABLE IF NOT EXISTS binaries
(
    bin_id   INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    name     TEXT,
    arch     TEXT,
    sha256   TEXT    NOT NULL,
    last_run TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS binaries_hash_uindex ON binaries (sha256);

CREATE TABLE IF NOT EXISTS gadget_errors
(
    binary  INTEGER REFERENCES binaries ON UPDATE CASCADE ON DELETE CASCADE,
    address INTEGER,
    info    TEXT,
    CONSTRAINT gadget_errors_pk PRIMARY KEY (binary, address)
);

CREATE TABLE IF NOT EXISTS gadgets
(
    binary              INTEGER NOT NULL REFERENCES binaries ON UPDATE CASCADE ON DELETE CASCADE,
    address             INTEGER NOT NULL,
    address_hex         TEXT,
    valid               INTEGER,
    intended            INTEGER,
    return_type         TEXT,
    ra                  TEXT,
    ip_constraints      TEXT,
    pop_size            INTEGER,
    reg_stack_read      TEXT,
    reg_moved           TEXT,
    reg_other           TEXT,
    solver_constraints  TEXT,
    instruction_count   INTEGER,
    instructions        TEXT,
    last_instr          TEXT,
    last_instr_addr     INTEGER,
    last_instr_addr_hex TEXT,
    atime               TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT gadgets_pk PRIMARY KEY (BINARY, address)
);
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = TRUE;
