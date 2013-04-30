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

    Регистрация страниц сайта
*/

/* ------------------------------------------------------------------------- */

\set AID ws.class_id('account')
\set TID ws.class_id('team')

INSERT INTO i18n_def.page (code, up_code, class_id, action_id, sort, uri, tmpl, name) VALUES
  ('info.prop',            'group.info',          1,    3, 10, 'info/prop$',                 'app_sample/prop/index',        'Параметры системы')
, ('account.id.prop',      'group.account.setup', :AID, 2, 2,  'account/:i/setup/prop$',     'app_sample/prop/account',      'Параметры')
, ('team.id.prop',         'group.team.setup',    :TID, 2, 2,  'team/:i/setup/prop$',        'app_sample/prop/team',         'Параметры')

, ('account.id.file',      'account.id',          :AID, 2, 2,  'account/:i/file$',           'acc/account/-id/files',        'Файлы')
, ('team.id.file',         'team.id',             :TID, 2, 2,  'team/:i/file$',              'acc/team/-id/files',           'Файлы')

, ('account.fs',           'account.id',          :AID, 2, 2,  'account/:i/:s:u$',           'fs/file',                      'Файлы')
, ('team.fs',              'team.id',             :TID, 2, 2,  'team/:i/:s:u$',              'fs/file',                      'Файлы')
;

INSERT INTO i18n_def.page (code, up_code, class_id, action_id, uri, tmpl, name) VALUES
  ('info.prop.edit',       'info.prop',           1,    3, 'info/prop/edit/:s$',             'app_sample/prop/edit/index',   'Редактирование параметров системы')
, ('account.id.prop.edit', 'account.id.prop',     :AID, 2, 'account/:i/setup/prop/edit/:s$', 'app_sample/prop/edit/account', 'Редактирование параметров')
, ('team.id.prop.edit',    'team.id.prop',        :TID, 2, 'team/:i/setup/prop/edit/:s$',    'app_sample/prop/edit/team',    'Редактирование параметров')
