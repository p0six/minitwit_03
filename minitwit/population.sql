insert into user (username, email, pw_hash) values ('mike', 'romerom@gmail.com', 'pbkdf2:sha256:50000$7VKjFQZP$da63f8b89e016788e6e58245f242e13d55f73d15b83c47c6af606d92bbe1dd52');
insert into user (username, email, pw_hash) values ('ninjitsu', 'romerom@csu.fullerton.edu', 'pbkdf2:sha256:50000$7VKjFQZP$da63f8b89e016788e6e58245f242e13d55f73d15b83c47c6af606d92bbe1dd52');
insert into user (username, email, pw_hash) values ('romerom', 'theromerom@yahoo.com', 'pbkdf2:sha256:50000$7VKjFQZP$da63f8b89e016788e6e58245f242e13d55f73d15b83c47c6af606d92bbe1dd52');
insert into user (username, email, pw_hash) values ('exeternal', 'theromerom@msn.com', 'pbkdf2:sha256:50000$7VKjFQZP$da63f8b89e016788e6e58245f242e13d55f73d15b83c47c6af606d92bbe1dd52');

insert into follower (who_id, whom_id) values (2,1);
insert into follower (who_id, whom_id) values (3,2);
insert into follower (who_id, whom_id) values (3,1);
insert into follower (who_id, whom_id) values (4,1);
insert into follower (who_id, whom_id) values (4,2);
insert into follower (who_id, whom_id) values (4,3);

insert into message (author_id, text, pub_date) values (1, "mike's first tweet!", 1505497625);
insert into message (author_id, text, pub_date) values (2, "ninjitsu the ginsu's 1st!", 1505497635);
insert into message (author_id, text, pub_date) values (1, "mike's second tweet!", 1505497645);
insert into message (author_id, text, pub_date) values (1, "mike's third tweet!", 1505497655);
insert into message (author_id, text, pub_date) values (2, "ninjitsu the ginsu's 2nd!", 1505497665);
insert into message (author_id, text, pub_date) values (3, "wtf is a romerom numba 1!", 1505497675);
insert into message (author_id, text, pub_date) values (3, "romerom like romadon?", 1505497685);
insert into message (author_id, text, pub_date) values (4, "exeternal from ingress?", 1505497695);
insert into message (author_id, text, pub_date) values (4, "yes for sure?", 1505497705);
insert into message (author_id, text, pub_date) values (1, "i follow nobody. nerds!", 1505497715);
