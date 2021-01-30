CREATE TABLE IF NOT EXISTS user (
  userid VARCHAR(32) PRIMARY KEY,
  password VARCHAR(64) NOT NULL,
  refreshtoken VARCHAR(64),
  refreshtoken_iat TIMESTAMP
);
