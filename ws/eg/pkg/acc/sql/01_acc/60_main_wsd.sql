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

    Функции триггеров пакета acc
*/

/* ------------------------------------------------------------------------- */
CREATE OR REPLACE FUNCTION account_contact_insupd_trigger() RETURNS TRIGGER IMMUTABLE LANGUAGE 'plpgsql' AS
$_$
  DECLARE
    v_rows INTEGER;
  BEGIN
      SELECT INTO v_rows
        count(1)
        FROM wsd.account
        WHERE NEW.account_id = id
      ;

    IF v_rows = 0 THEN
      RAISE EXCEPTION 'Not account with id=%', NEW.account_id;
    END IF;

    RETURN NEW;
  END;
$_$;
SELECT pg_c('f', 'account_contact_insupd_trigger', 'Проверка наличия пользователя для контакта');

/* ------------------------------------------------------------------------- */
CREATE OR REPLACE FUNCTION validation_email_trigger() RETURNS TRIGGER IMMUTABLE LANGUAGE 'plpgsql' AS
$_$
  BEGIN

    IF NEW.value !~ E'(?:^$|^[^ ]+@[^ ]+\\.[^ ]{2,6}$)' THEN
      RAISE EXCEPTION '%', ws.perror_str(acc.const_error_email_validation(), 'value', NEW.value);
    END IF;

    RETURN NEW;
  END;
$_$;
SELECT pg_c('f', 'validation_email_trigger', 'Проверка валидности email');

/* ------------------------------------------------------------------------- */
CREATE OR REPLACE FUNCTION validation_phone_trigger() RETURNS TRIGGER IMMUTABLE LANGUAGE 'plpgsql' AS
$_$
  BEGIN

    IF NEW.value !~ E'^((8|\\+7)[\\- ]?)?(\\(?\\d{3,5}\\)?[\\- ]?)?[\\d\\- ]{5,10}$' THEN
      RAISE EXCEPTION '%', ws.perror_str(acc.const_error_mobile_phone_validation(), 'value', NEW.value);
    END IF;

    RETURN NEW;
  END;
$_$;
SELECT pg_c('f', 'validation_phone_trigger', 'Проверка валидности номера телефона');

/* ------------------------------------------------------------------------- */
CREATE OR REPLACE FUNCTION tr_block_login() RETURNS trigger LANGUAGE 'plpgsql' AS
$_$
  DECLARE
    r           wsd.account;
    r_prop      RECORD;
    v_cnt_sgn   BOOLEAN;
    v_time      TIMESTAMP;
    v_id        INTEGER;
  BEGIN
    SELECT INTO r
      *
      FROM wsd.account
      WHERE login = NEW.login
    ;
    --Извлекаем настройки :кол-во попыток входа,интервал попыток входа и интервал блокировки.
    SELECT INTO r_prop 
      COALESCE(a.value::INT,a.def_value::INT)       AS pac,
      COALESCE(b.value||' minute',b.def_value||' minute') AS pai ,
      COALESCE(c.value||' minute',c.def_value||' minute') AS pli
      FROM acc.prop_attr_team_isv(r.id, 'password_attempt_count') a
         , acc.prop_attr_team_isv(r.id, 'password_attempt_interval') b
         , acc.prop_attr_team_isv(r.id, 'password_lock_interval') c 
    ;
    --Условие выполняется? Превышение кол-ва попыток за заданный интервал .
    SELECT INTO v_cnt_sgn count(1) > r_prop.pac 
      FROM acc.sign_log 
      WHERE login = NEW.login 
      AND try_at > now() - r_prop.pai::INTERVAL
    ;
    IF v_cnt_sgn THEN
      --Создаём задачу блокировки логина на интервал блокировки с текущего момента.
      v_id := NEXTVAL('wsd.event_reason_seq');
      v_time:=CURRENT_TIMESTAMP(0);
      PERFORM job.create_at(v_time, job.handler_id('acc.account_set_blocked'), 2, r.id, CURRENT_DATE, v_id, a_more:=r_prop.pli);
    END IF;          
    RETURN NEW;
  END;
$_$;
SELECT pg_c('f', 'tr_block_login', 'Проверка условия блокировки логина');
