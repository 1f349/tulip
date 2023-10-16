CREATE TABLE IF NOT EXISTS users
(
    subject        TEXT PRIMARY KEY UNIQUE     NOT NULL,
    name           TEXT                        NOT NULL,
    username       TEXT UNIQUE                 NOT NULL,
    password       TEXT                        NOT NULL,
    picture        TEXT    DEFAULT ""          NOT NULL,
    website        TEXT    DEFAULT ""          NOT NULL,
    email          TEXT                        NOT NULL,
    email_verified INTEGER DEFAULT 0           NOT NULL,
    pronouns       TEXT    DEFAULT "they/them" NOT NULL,
    birthdate      DATE,
    zoneinfo       TEXT    DEFAULT "UTC"       NOT NULL,
    locale         TEXT    DEFAULT "en-US"     NOT NULL,
    role           INTEGER DEFAULT 0           NOT NULL,
    updated_at     DATETIME,
    registered     INTEGER DEFAULT 0,
    active         INTEGER DEFAULT 1
);

CREATE UNIQUE INDEX IF NOT EXISTS username_index ON users (username);

CREATE TABLE IF NOT EXISTS client_store
(
    subject TEXT PRIMARY KEY UNIQUE NOT NULL,
    name    TEXT                    NOT NULL,
    secret  TEXT UNIQUE             NOT NULL,
    domain  TEXT                    NOT NULL,
    owner   TEXT                    NOT NULL,
    sso     INTEGER,
    active  INTEGER DEFAULT 1,
    FOREIGN KEY (owner) REFERENCES users (subject)
);

CREATE TABLE IF NOT EXISTS otp
(
    subject TEXT PRIMARY KEY UNIQUE NOT NULL,
    secret  TEXT                    NOT NULL,
    digits  INTEGER                 NOT NULL,
    FOREIGN KEY (subject) REFERENCES users (subject)
);
