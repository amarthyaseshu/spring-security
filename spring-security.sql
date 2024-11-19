
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT,
    password TEXT
);


CREATE TABLE refresh_token (
    id INTEGER PRIMARY KEY,
    token TEXT,
    expiry_date TIMESTAMP,
    user_id INTEGER, 
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

select * from users;
select * from refresh_token;