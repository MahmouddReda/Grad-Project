create database vscan;
use vscan;
create table users(
	id int auto_increment primary key,
    firstname varchar(100) not null,
    lastname varchar(100) not null,
    email varchar(255) not null unique,
    password varchar(255) not null,
    createdat timestamp default current_timestamp
);

create table scans(
   id int auto_increment primary key,
   user_id int not null,
   target_url varchar(255) not null,
   vuln_count int default 0,
   vuln_types varchar(255),
   scan_date timestamp default current_timestamp,
   foreign key (user_id) references users(id)
);

delete from users;
