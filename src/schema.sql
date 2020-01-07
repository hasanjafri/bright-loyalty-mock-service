DROP TABLE IF EXISTS admin;

DROP TABLE IF EXISTS vendor;

DROP TABLE IF EXISTS party;

DROP TABLE IF EXISTS theme;

DROP TABLE IF EXISTS customer;

CREATE TABLE admin (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE vendor (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE party (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    vendors TEXT NOT NULL,
    vendor_id INTEGER,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vendor_id) REFERENCES vendor (id)
);

CREATE TABLE theme (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    primary_color TEXT NOT NULL,
    secondary_color TEXT NOT NULL,
    accent TEXT NOT NULL,
    admin_id INTEGER,
    party_id INTEGER,
    vendor_id INTEGER,
    FOREIGN KEY (admin_id) REFERENCES admin (id),
    FOREIGN KEY (party_id) REFERENCES party (id),
    FOREIGN KEY (vendor_id) REFERENCES vendor (id)
)