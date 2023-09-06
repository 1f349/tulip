CREATE TABLE IF NOT EXISTS users
(
    subject        TEXT PRIMARY KEY UNIQUE     NOT NULL,
    name           TEXT                        NOT NULL,
    username       TEXT UNIQUE                 NOT NULL,
    password       TEXT                        NOT NULL,
    picture        TEXT,
    website        TEXT,
    email          TEXT                        NOT NULL,
    email_verified INTEGER DEFAULT 0           NOT NULL,
    pronouns       TEXT    DEFAULT "they/them" NOT NULL,
    birthdate      DATE,
    zoneinfo       TEXT    DEFAULT ""          NOT NULL,
    locale         TEXT    DEFAULT "en-US"     NOT NULL,
    updated_at     DATETIME,
    active         INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS client_store
(
    subject TEXT PRIMARY KEY UNIQUE NOT NULL,
    name    TEXT UNIQUE             NOT NULL,
    secret  TEXT UNIQUE             NOT NULL,
    domain  TEXT                    NOT NULL,
    sso     INTEGER,
    active  INTEGER DEFAULT 1
);
