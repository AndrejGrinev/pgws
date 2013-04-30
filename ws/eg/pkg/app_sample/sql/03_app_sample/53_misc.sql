
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

    Метод API add
*/

/* ------------------------------------------------------------------------- */
CREATE OR REPLACE FUNCTION generate_team (a_team_count d_cnt, a_member_max d_cnt, a_psw TEXT, a_promo_code text DEFAULT NULL) RETURNS TEXT LANGUAGE 'plpgsql' AS
$_$
-- a_team_count: Количество автоматически создаваемых команд
-- a_member_max: Максимальное количество участников в команде
-- a_promo_code: Код сгенерированных команд
DECLARE
  v_team_id ws.d_id;
  v_account_id ws.d_id;
  v_member_max integer;
  v_promo_code text;
  v_t integer;
  v_a integer;
BEGIN
  v_promo_code := COALESCE(a_promo_code, to_char(now(), 'YYMMDDHH24MI'));
  FOR v_t IN 1..a_team_count
  LOOP
    INSERT INTO wsd.team(name, status_id) VALUES (
      'Autogenerated team #' || v_t::text
      , acc.const_team_status_id_active()
    ) RETURNING id INTO v_team_id
    ;
    PERFORM cfg.prop_value_edit(acc.const_team_group_prop(), v_team_id::ws.d_id, 'object.promo'::cfg.d_prop_code, v_promo_code);
    v_member_max := (random() * a_member_max::integer + 1)::integer;
    FOR v_a IN 1..v_member_max
    LOOP
      INSERT INTO wsd.account(status_id, login, psw, name) VALUES (
        acc.const_status_id_active()
      , v_team_id::text ||'_acc_' || v_a::text
      , a_psw
      , 'Autogenerated account #' || v_a::text || ' / ' || v_team_id::text 
      ) RETURNING id INTO v_account_id
      ;
      INSERT INTO wsd.account_team(account_id, team_id, role_id) VALUES (
        v_account_id
      , v_team_id
      , CASE WHEN v_a = 1 THEN 8                        -- admin role
             WHEN v_a != 1 AND random() < 0.6 THEN 5    -- writer role
             ELSE 6                                     -- editor role
        END
      );
      PERFORM cfg.prop_value_edit(acc.const_account_group_prop(), v_account_id::ws.d_id, 'object.promo'::cfg.d_prop_code, v_promo_code);
    END LOOP;
  END LOOP;
  RETURN v_promo_code;
END;
$_$;
SELECT pg_c('f', 'generate_team', 'Автоматическая генерация команд');

/* ------------------------------------------------------------------------- */
CREATE OR REPLACE FUNCTION drop_generated_team (a_promo_code text) RETURNS BOOL LANGUAGE 'sql' AS
$_$
  DELETE FROM wsd.account_team
    WHERE cfg.prop_value(acc.const_account_group_prop(), account_id, 'object.promo'::cfg.d_prop_code) = $1;
  DELETE FROM wsd.account
    WHERE cfg.prop_value(acc.const_account_group_prop(), id, 'object.promo'::cfg.d_prop_code) = $1;
  DELETE FROM wsd.team
    WHERE cfg.prop_value(acc.const_team_group_prop(), id, 'object.promo'::cfg.d_prop_code) = $1;
  SELECT TRUE;
$_$;
SELECT pg_c('f', 'drop_generated_team', 'Удаление автоматически созданных команд');

/* ------------------------------------------------------------------------- */
