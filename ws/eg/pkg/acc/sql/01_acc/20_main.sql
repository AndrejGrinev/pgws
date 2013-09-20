/*

    Copyright (c) 2010, 2012 Tender.Pro http://tender.pro.

    This file is part of PGWS - Postgresql WebServices.

    PGWS is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    PGWS is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with PGWS.  If not, see <http://www.gnu.org/licenses/>.

*/
/* ------------------------------------------------------------------------- */

CREATE TABLE class_link (
  class_id   d_class  NOT NULL REFERENCES class ON DELETE CASCADE
, id         d_id32   NOT NULL
, name       d_string NOT NULL
, CONSTRAINT class_link_pkey PRIMARY KEY (class_id, id)
);
SELECT pg_c('r', 'class_link', 'Связи класса описывают разрешения на уровне владельцев')
, pg_c('c', 'class_link.class_id',  'ID класса')
, pg_c('c', 'class_link.id',        'ID связи')
, pg_c('c', 'class_link.name',      'Название связи')
;

/* ------------------------------------------------------------------------- */
CREATE TABLE team_link (
  id      d_id32        NOT NULL PRIMARY KEY
, name    d_string      NOT NULL
);
SELECT pg_c('r', 'team_link', 'Справочник возможных видов связи между компаниями')
, pg_c('c', 'team_link.id',        'ID связи')
, pg_c('c', 'team_link.name',      'Название связи')
;

/* ------------------------------------------------------------------------- */
CREATE TABLE account_contact_type (
  id      d_id32        NOT NULL PRIMARY KEY
, name    d_string      NOT NULL
);
SELECT pg_c('r', 'account_contact_type', 'Справочник типов контактных данных')
, pg_c('c', 'account_contact_type.id',        'ID типа')
, pg_c('c', 'account_contact_type.name',      'Название типа контакта')
;

/* ------------------------------------------------------------------------- */
CREATE TABLE acc.sign_log (
  id     INTEGER                        PRIMARY KEY
, login  TEXT                           NOT NULL
, try_at TIMESTAMP(0) without time zone NOT NULL DEFAULT CURRENT_TIMESTAMP
, ip     TEXT                           NOT NULL
);
SELECT ws.pg_c('r', 'acc.sign_log',   'Лог входов с неправильным паролем')
, ws.pg_c('c', 'acc.sign_log.id',     'идентификатор')
, ws.pg_c('c', 'acc.sign_log.login',  'логин')
, ws.pg_c('c', 'acc.sign_log.try_at', 'время входа')
, ws.pg_c('c', 'acc.sign_log.ip',     'ip')
;

CREATE SEQUENCE acc.sign_log_id_seq;
ALTER TABLE acc.sign_log ALTER COLUMN id SET DEFAULT NEXTVAL('acc.sign_log_id_seq');
