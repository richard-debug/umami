create table "ip_reputation_hit" (
  "website_id" uuid not null,
  "ip" varchar(45) not null,
  "source" varchar(64) not null,
  "observed_date" date not null,
  "first_seen_at" timestamptz(6) not null,
  "last_seen_at" timestamptz(6) not null,
  "hit_count" integer not null default 1,

  constraint "ip_reputation_hit_pkey"
    primary key ("website_id", "ip", "source", "observed_date")
);

create index "ip_reputation_hit_website_id_observed_date_idx"
  on "ip_reputation_hit"("website_id", "observed_date");

create index "ip_reputation_hit_website_id_last_seen_at_idx"
  on "ip_reputation_hit"("website_id", "last_seen_at");

alter table "ip_reputation_hit"
  add constraint "ip_reputation_hit_website_id_fkey"
  foreign key ("website_id") references "website"("website_id")
  on delete cascade on update cascade;
