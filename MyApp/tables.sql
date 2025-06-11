CREATE DATABASE CTKapp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE CTKapp;

CREATE TABLE user (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id VARCHAR(32) UNIQUE,
    username VARCHAR(80) UNIQUE,
    email VARCHAR(120) UNIQUE,
    phone VARCHAR(20) UNIQUE,
    password VARCHAR(128),
    name VARCHAR(80),
    contact VARCHAR(80),
    avatar VARCHAR(200) DEFAULT '/static/images/default-user.png',
    theme VARCHAR(10) DEFAULT 'light',
    is_admin BOOLEAN DEFAULT 0
);

CREATE TABLE room (
    id INT PRIMARY KEY AUTO_INCREMENT,
    code VARCHAR(8) UNIQUE NOT NULL,
    name VARCHAR(80),
    icon VARCHAR(200) DEFAULT '/static/images/default-room.png',
    wallpaper VARCHAR(200) DEFAULT '',
    creator_id INT,
    FOREIGN KEY (creator_id) REFERENCES user(id)
);

CREATE TABLE room_member (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    room_id INT,
    last_opened DATETIME,
    status ENUM('pending','approved','rejected') DEFAULT 'pending',
    FOREIGN KEY (user_id) REFERENCES user(id),
    FOREIGN KEY (room_id) REFERENCES room(id)
);

CREATE TABLE message (
    id INT PRIMARY KEY AUTO_INCREMENT,
    room_id INT,
    user_id INT,
    content TEXT,
    file_url VARCHAR(200),
    file_type VARCHAR(20),
    is_broadcast BOOLEAN DEFAULT 0,
    timestamp DATETIME,
    FOREIGN KEY (room_id) REFERENCES room(id),
    FOREIGN KEY (user_id) REFERENCES user(id)
);

CREATE TABLE status (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    content TEXT,
    file_url VARCHAR(200),
    file_type VARCHAR(20),
    timestamp DATETIME,
    view_count INT DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES user(id)
);

CREATE TABLE status_view (
    id INT PRIMARY KEY AUTO_INCREMENT,
    status_id INT,
    viewer_id INT,
    timestamp DATETIME,
    FOREIGN KEY (status_id) REFERENCES status(id),
    FOREIGN KEY (viewer_id) REFERENCES user(id)
);

CREATE TABLE notification (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    message TEXT,
    is_read BOOLEAN DEFAULT 0,
    type ENUM('join_request','admin_msg','approval','broadcast'),
    room_id INT,
    timestamp DATETIME,
    FOREIGN KEY (user_id) REFERENCES user(id),
    FOREIGN KEY (room_id) REFERENCES room(id)
);

ALTER TABLE user MODIFY password TEXT;

select * from user;
select * from room;
select * from notification;
select * from status;
select * from status_view;
select * from room_member;
select * from message;

#drop database ctkapp;
update user set password='Rikki@281125' where id=6;

insert into user values(8,"Venu_25@CTKVoila","Venu@25","venuvenu@gmail.com","7901239018","Venu@12345","Venu","
