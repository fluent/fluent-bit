/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_compat.h>

#include <stddef.h>
#include <string.h>
#include <stdlib.h>

struct flb_time_tz_map {
    const char *windows;
    const char *iana;
    /* Standard UTC offset in seconds; dynamic DST offsets require IANA tzdb. */
    long utc_offset;
};

#define FLB_TZ_UTC_OFFSET(hours, minutes) \
    ((((hours) * 60) + (minutes)) * 60L)

static const struct flb_time_tz_map windows_iana_timezones[] = {
    { "Dateline Standard Time", "Etc/GMT+12", FLB_TZ_UTC_OFFSET(-12, 0) },
    { "UTC-11", "Etc/GMT+11", FLB_TZ_UTC_OFFSET(-11, 0) },
    { "UTC-11", "Pacific/Pago_Pago", FLB_TZ_UTC_OFFSET(-11, 0) },
    { "UTC-11", "Pacific/Niue", FLB_TZ_UTC_OFFSET(-11, 0) },
    { "UTC-11", "Pacific/Midway", FLB_TZ_UTC_OFFSET(-11, 0) },
    { "Aleutian Standard Time", "America/Adak", FLB_TZ_UTC_OFFSET(-10, 0) },
    { "Hawaiian Standard Time", "Pacific/Honolulu", FLB_TZ_UTC_OFFSET(-10, 0) },
    { "Hawaiian Standard Time", "Pacific/Rarotonga", FLB_TZ_UTC_OFFSET(-10, 0) },
    { "Hawaiian Standard Time", "Pacific/Tahiti", FLB_TZ_UTC_OFFSET(-10, 0) },
    { "Hawaiian Standard Time", "Pacific/Johnston", FLB_TZ_UTC_OFFSET(-10, 0) },
    { "Hawaiian Standard Time", "Etc/GMT+10", FLB_TZ_UTC_OFFSET(-10, 0) },
    { "Marquesas Standard Time", "Pacific/Marquesas", FLB_TZ_UTC_OFFSET(-9, -30) },
    { "Alaskan Standard Time", "America/Anchorage", FLB_TZ_UTC_OFFSET(-9, 0) },
    { "Alaskan Standard Time", "America/Juneau", FLB_TZ_UTC_OFFSET(-9, 0) },
    { "Alaskan Standard Time", "America/Metlakatla", FLB_TZ_UTC_OFFSET(-9, 0) },
    { "Alaskan Standard Time", "America/Nome", FLB_TZ_UTC_OFFSET(-9, 0) },
    { "Alaskan Standard Time", "America/Sitka", FLB_TZ_UTC_OFFSET(-9, 0) },
    { "Alaskan Standard Time", "America/Yakutat", FLB_TZ_UTC_OFFSET(-9, 0) },
    { "UTC-09", "Etc/GMT+9", FLB_TZ_UTC_OFFSET(-9, 0) },
    { "UTC-09", "Pacific/Gambier", FLB_TZ_UTC_OFFSET(-9, 0) },
    { "Pacific Standard Time (Mexico)", "America/Tijuana", FLB_TZ_UTC_OFFSET(-8, 0) },
    { "Pacific Standard Time (Mexico)", "America/Santa_Isabel", FLB_TZ_UTC_OFFSET(-8, 0) },
    { "UTC-08", "Etc/GMT+8", FLB_TZ_UTC_OFFSET(-8, 0) },
    { "UTC-08", "Pacific/Pitcairn", FLB_TZ_UTC_OFFSET(-8, 0) },
    { "Pacific Standard Time", "America/Los_Angeles", FLB_TZ_UTC_OFFSET(-8, 0) },
    { "Pacific Standard Time", "America/Vancouver", FLB_TZ_UTC_OFFSET(-8, 0) },
    { "Pacific Standard Time", "PST8PDT", FLB_TZ_UTC_OFFSET(-8, 0) },
    { "US Mountain Standard Time", "America/Phoenix", FLB_TZ_UTC_OFFSET(-7, 0) },
    { "US Mountain Standard Time", "America/Creston", FLB_TZ_UTC_OFFSET(-7, 0) },
    { "US Mountain Standard Time", "America/Dawson_Creek", FLB_TZ_UTC_OFFSET(-7, 0) },
    { "US Mountain Standard Time", "America/Fort_Nelson", FLB_TZ_UTC_OFFSET(-7, 0) },
    { "US Mountain Standard Time", "America/Hermosillo", FLB_TZ_UTC_OFFSET(-7, 0) },
    { "US Mountain Standard Time", "Etc/GMT+7", FLB_TZ_UTC_OFFSET(-7, 0) },
    { "Mountain Standard Time (Mexico)", "America/Chihuahua", FLB_TZ_UTC_OFFSET(-7, 0) },
    { "Mountain Standard Time (Mexico)", "America/Mazatlan", FLB_TZ_UTC_OFFSET(-7, 0) },
    { "Mountain Standard Time", "America/Denver", FLB_TZ_UTC_OFFSET(-7, 0) },
    { "Mountain Standard Time", "America/Edmonton", FLB_TZ_UTC_OFFSET(-7, 0) },
    { "Mountain Standard Time", "America/Cambridge_Bay", FLB_TZ_UTC_OFFSET(-7, 0) },
    { "Mountain Standard Time", "America/Inuvik", FLB_TZ_UTC_OFFSET(-7, 0) },
    { "Mountain Standard Time", "America/Yellowknife", FLB_TZ_UTC_OFFSET(-7, 0) },
    { "Mountain Standard Time", "America/Ojinaga", FLB_TZ_UTC_OFFSET(-7, 0) },
    { "Mountain Standard Time", "America/Boise", FLB_TZ_UTC_OFFSET(-7, 0) },
    { "Mountain Standard Time", "MST7MDT", FLB_TZ_UTC_OFFSET(-7, 0) },
    { "Yukon Standard Time", "America/Whitehorse", FLB_TZ_UTC_OFFSET(-7, 0) },
    { "Yukon Standard Time", "America/Dawson", FLB_TZ_UTC_OFFSET(-7, 0) },
    { "Central America Standard Time", "America/Guatemala", FLB_TZ_UTC_OFFSET(-6, 0) },
    { "Central America Standard Time", "America/Belize", FLB_TZ_UTC_OFFSET(-6, 0) },
    { "Central America Standard Time", "America/Costa_Rica", FLB_TZ_UTC_OFFSET(-6, 0) },
    { "Central America Standard Time", "Pacific/Galapagos", FLB_TZ_UTC_OFFSET(-6, 0) },
    { "Central America Standard Time", "America/Tegucigalpa", FLB_TZ_UTC_OFFSET(-6, 0) },
    { "Central America Standard Time", "America/Managua", FLB_TZ_UTC_OFFSET(-6, 0) },
    { "Central America Standard Time", "America/El_Salvador", FLB_TZ_UTC_OFFSET(-6, 0) },
    { "Central America Standard Time", "Etc/GMT+6", FLB_TZ_UTC_OFFSET(-6, 0) },
    { "Central Standard Time", "America/Chicago", FLB_TZ_UTC_OFFSET(-6, 0) },
    { "Central Standard Time", "America/Winnipeg", FLB_TZ_UTC_OFFSET(-6, 0) },
    { "Central Standard Time", "America/Rainy_River", FLB_TZ_UTC_OFFSET(-6, 0) },
    { "Central Standard Time", "America/Rankin_Inlet", FLB_TZ_UTC_OFFSET(-6, 0) },
    { "Central Standard Time", "America/Resolute", FLB_TZ_UTC_OFFSET(-6, 0) },
    { "Central Standard Time", "America/Matamoros", FLB_TZ_UTC_OFFSET(-6, 0) },
    { "Central Standard Time", "America/Indiana/Knox", FLB_TZ_UTC_OFFSET(-6, 0) },
    { "Central Standard Time", "America/Indiana/Tell_City", FLB_TZ_UTC_OFFSET(-6, 0) },
    { "Central Standard Time", "America/Menominee", FLB_TZ_UTC_OFFSET(-6, 0) },
    { "Central Standard Time", "America/North_Dakota/Beulah", FLB_TZ_UTC_OFFSET(-6, 0) },
    { "Central Standard Time", "America/North_Dakota/Center", FLB_TZ_UTC_OFFSET(-6, 0) },
    { "Central Standard Time", "America/North_Dakota/New_Salem", FLB_TZ_UTC_OFFSET(-6, 0) },
    { "Central Standard Time", "CST6CDT", FLB_TZ_UTC_OFFSET(-6, 0) },
    { "Easter Island Standard Time", "Pacific/Easter", FLB_TZ_UTC_OFFSET(-6, 0) },
    { "Central Standard Time (Mexico)", "America/Mexico_City", FLB_TZ_UTC_OFFSET(-6, 0) },
    { "Central Standard Time (Mexico)", "America/Bahia_Banderas", FLB_TZ_UTC_OFFSET(-6, 0) },
    { "Central Standard Time (Mexico)", "America/Merida", FLB_TZ_UTC_OFFSET(-6, 0) },
    { "Central Standard Time (Mexico)", "America/Monterrey", FLB_TZ_UTC_OFFSET(-6, 0) },
    { "Canada Central Standard Time", "America/Regina", FLB_TZ_UTC_OFFSET(-6, 0) },
    { "Canada Central Standard Time", "America/Swift_Current", FLB_TZ_UTC_OFFSET(-6, 0) },
    { "SA Pacific Standard Time", "America/Bogota", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "SA Pacific Standard Time", "America/Rio_Branco", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "SA Pacific Standard Time", "America/Eirunepe", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "SA Pacific Standard Time", "America/Coral_Harbour", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "SA Pacific Standard Time", "America/Guayaquil", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "SA Pacific Standard Time", "America/Jamaica", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "SA Pacific Standard Time", "America/Cayman", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "SA Pacific Standard Time", "America/Panama", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "SA Pacific Standard Time", "America/Lima", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "SA Pacific Standard Time", "Etc/GMT+5", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "Eastern Standard Time (Mexico)", "America/Cancun", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "Eastern Standard Time", "America/New_York", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "Eastern Standard Time", "America/Nassau", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "Eastern Standard Time", "America/Toronto", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "Eastern Standard Time", "America/Iqaluit", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "Eastern Standard Time", "America/Montreal", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "Eastern Standard Time", "America/Nipigon", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "Eastern Standard Time", "America/Pangnirtung", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "Eastern Standard Time", "America/Thunder_Bay", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "Eastern Standard Time", "America/Detroit", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "Eastern Standard Time", "America/Indiana/Petersburg", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "Eastern Standard Time", "America/Indiana/Vincennes", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "Eastern Standard Time", "America/Indiana/Winamac", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "Eastern Standard Time", "America/Kentucky/Monticello", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "Eastern Standard Time", "America/Louisville", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "Eastern Standard Time", "EST5EDT", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "Haiti Standard Time", "America/Port-au-Prince", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "Cuba Standard Time", "America/Havana", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "US Eastern Standard Time", "America/Indianapolis", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "US Eastern Standard Time", "America/Indiana/Marengo", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "US Eastern Standard Time", "America/Indiana/Vevay", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "Turks And Caicos Standard Time", "America/Grand_Turk", FLB_TZ_UTC_OFFSET(-5, 0) },
    { "Paraguay Standard Time", "America/Asuncion", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "Atlantic Standard Time", "America/Halifax", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "Atlantic Standard Time", "Atlantic/Bermuda", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "Atlantic Standard Time", "America/Glace_Bay", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "Atlantic Standard Time", "America/Goose_Bay", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "Atlantic Standard Time", "America/Moncton", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "Atlantic Standard Time", "America/Thule", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "Venezuela Standard Time", "America/Caracas", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "Central Brazilian Standard Time", "America/Cuiaba", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "Central Brazilian Standard Time", "America/Campo_Grande", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "SA Western Standard Time", "America/La_Paz", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "SA Western Standard Time", "America/Antigua", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "SA Western Standard Time", "America/Anguilla", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "SA Western Standard Time", "America/Aruba", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "SA Western Standard Time", "America/Barbados", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "SA Western Standard Time", "America/St_Barthelemy", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "SA Western Standard Time", "America/Kralendijk", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "SA Western Standard Time", "America/Manaus", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "SA Western Standard Time", "America/Boa_Vista", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "SA Western Standard Time", "America/Porto_Velho", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "SA Western Standard Time", "America/Blanc-Sablon", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "SA Western Standard Time", "America/Curacao", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "SA Western Standard Time", "America/Dominica", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "SA Western Standard Time", "America/Santo_Domingo", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "SA Western Standard Time", "America/Grenada", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "SA Western Standard Time", "America/Guadeloupe", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "SA Western Standard Time", "America/Guyana", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "SA Western Standard Time", "America/St_Kitts", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "SA Western Standard Time", "America/St_Lucia", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "SA Western Standard Time", "America/Marigot", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "SA Western Standard Time", "America/Martinique", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "SA Western Standard Time", "America/Montserrat", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "SA Western Standard Time", "America/Puerto_Rico", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "SA Western Standard Time", "America/Lower_Princes", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "SA Western Standard Time", "America/Port_of_Spain", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "SA Western Standard Time", "America/St_Vincent", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "SA Western Standard Time", "America/Tortola", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "SA Western Standard Time", "America/St_Thomas", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "SA Western Standard Time", "Etc/GMT+4", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "Pacific SA Standard Time", "America/Santiago", FLB_TZ_UTC_OFFSET(-4, 0) },
    { "Newfoundland Standard Time", "America/St_Johns", FLB_TZ_UTC_OFFSET(-3, -30) },
    { "Tocantins Standard Time", "America/Araguaina", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "E. South America Standard Time", "America/Sao_Paulo", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "SA Eastern Standard Time", "America/Cayenne", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "SA Eastern Standard Time", "Antarctica/Rothera", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "SA Eastern Standard Time", "Antarctica/Palmer", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "SA Eastern Standard Time", "America/Fortaleza", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "SA Eastern Standard Time", "America/Belem", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "SA Eastern Standard Time", "America/Maceio", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "SA Eastern Standard Time", "America/Santarem", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "SA Eastern Standard Time", "America/Recife", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "SA Eastern Standard Time", "Atlantic/Stanley", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "SA Eastern Standard Time", "America/Paramaribo", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "SA Eastern Standard Time", "Etc/GMT+3", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "Argentina Standard Time", "America/Buenos_Aires", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "Argentina Standard Time", "America/Argentina/La_Rioja", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "Argentina Standard Time", "America/Argentina/Rio_Gallegos", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "Argentina Standard Time", "America/Argentina/Salta", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "Argentina Standard Time", "America/Argentina/San_Juan", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "Argentina Standard Time", "America/Argentina/San_Luis", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "Argentina Standard Time", "America/Argentina/Tucuman", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "Argentina Standard Time", "America/Argentina/Ushuaia", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "Argentina Standard Time", "America/Catamarca", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "Argentina Standard Time", "America/Cordoba", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "Argentina Standard Time", "America/Jujuy", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "Argentina Standard Time", "America/Mendoza", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "Greenland Standard Time", "America/Nuuk", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "Greenland Standard Time", "America/Godthab", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "Montevideo Standard Time", "America/Montevideo", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "Magallanes Standard Time", "America/Punta_Arenas", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "Saint Pierre Standard Time", "America/Miquelon", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "Bahia Standard Time", "America/Bahia", FLB_TZ_UTC_OFFSET(-3, 0) },
    { "UTC-02", "Etc/GMT+2", FLB_TZ_UTC_OFFSET(-2, 0) },
    { "UTC-02", "America/Noronha", FLB_TZ_UTC_OFFSET(-2, 0) },
    { "UTC-02", "Atlantic/South_Georgia", FLB_TZ_UTC_OFFSET(-2, 0) },
    { "Azores Standard Time", "Atlantic/Azores", FLB_TZ_UTC_OFFSET(-1, 0) },
    { "Azores Standard Time", "America/Scoresbysund", FLB_TZ_UTC_OFFSET(-1, 0) },
    { "Cape Verde Standard Time", "Atlantic/Cape_Verde", FLB_TZ_UTC_OFFSET(-1, 0) },
    { "Cape Verde Standard Time", "Etc/GMT+1", FLB_TZ_UTC_OFFSET(-1, 0) },
    { "UTC", "Etc/UTC", FLB_TZ_UTC_OFFSET(0, 0) },
    { "UTC", "Etc/GMT", FLB_TZ_UTC_OFFSET(0, 0) },
    { "GMT Standard Time", "Europe/London", FLB_TZ_UTC_OFFSET(0, 0) },
    { "GMT Standard Time", "Atlantic/Canary", FLB_TZ_UTC_OFFSET(0, 0) },
    { "GMT Standard Time", "Atlantic/Faeroe", FLB_TZ_UTC_OFFSET(0, 0) },
    { "GMT Standard Time", "Europe/Guernsey", FLB_TZ_UTC_OFFSET(0, 0) },
    { "GMT Standard Time", "Europe/Dublin", FLB_TZ_UTC_OFFSET(0, 0) },
    { "GMT Standard Time", "Europe/Isle_of_Man", FLB_TZ_UTC_OFFSET(0, 0) },
    { "GMT Standard Time", "Europe/Jersey", FLB_TZ_UTC_OFFSET(0, 0) },
    { "GMT Standard Time", "Europe/Lisbon", FLB_TZ_UTC_OFFSET(0, 0) },
    { "GMT Standard Time", "Atlantic/Madeira", FLB_TZ_UTC_OFFSET(0, 0) },
    { "Greenwich Standard Time", "Atlantic/Reykjavik", FLB_TZ_UTC_OFFSET(0, 0) },
    { "Greenwich Standard Time", "Africa/Ouagadougou", FLB_TZ_UTC_OFFSET(0, 0) },
    { "Greenwich Standard Time", "Africa/Abidjan", FLB_TZ_UTC_OFFSET(0, 0) },
    { "Greenwich Standard Time", "Africa/Accra", FLB_TZ_UTC_OFFSET(0, 0) },
    { "Greenwich Standard Time", "America/Danmarkshavn", FLB_TZ_UTC_OFFSET(0, 0) },
    { "Greenwich Standard Time", "Africa/Banjul", FLB_TZ_UTC_OFFSET(0, 0) },
    { "Greenwich Standard Time", "Africa/Conakry", FLB_TZ_UTC_OFFSET(0, 0) },
    { "Greenwich Standard Time", "Africa/Bissau", FLB_TZ_UTC_OFFSET(0, 0) },
    { "Greenwich Standard Time", "Africa/Monrovia", FLB_TZ_UTC_OFFSET(0, 0) },
    { "Greenwich Standard Time", "Africa/Bamako", FLB_TZ_UTC_OFFSET(0, 0) },
    { "Greenwich Standard Time", "Africa/Nouakchott", FLB_TZ_UTC_OFFSET(0, 0) },
    { "Greenwich Standard Time", "Atlantic/St_Helena", FLB_TZ_UTC_OFFSET(0, 0) },
    { "Greenwich Standard Time", "Africa/Freetown", FLB_TZ_UTC_OFFSET(0, 0) },
    { "Greenwich Standard Time", "Africa/Dakar", FLB_TZ_UTC_OFFSET(0, 0) },
    { "Greenwich Standard Time", "Africa/Lome", FLB_TZ_UTC_OFFSET(0, 0) },
    { "Sao Tome Standard Time", "Africa/Sao_Tome", FLB_TZ_UTC_OFFSET(0, 0) },
    { "Morocco Standard Time", "Africa/Casablanca", FLB_TZ_UTC_OFFSET(1, 0) },
    { "Morocco Standard Time", "Africa/El_Aaiun", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Europe Standard Time", "Europe/Berlin", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Europe Standard Time", "Europe/Andorra", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Europe Standard Time", "Europe/Vienna", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Europe Standard Time", "Europe/Zurich", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Europe Standard Time", "Europe/Busingen", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Europe Standard Time", "Europe/Gibraltar", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Europe Standard Time", "Europe/Rome", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Europe Standard Time", "Europe/Vaduz", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Europe Standard Time", "Europe/Luxembourg", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Europe Standard Time", "Europe/Monaco", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Europe Standard Time", "Europe/Malta", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Europe Standard Time", "Europe/Amsterdam", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Europe Standard Time", "Europe/Oslo", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Europe Standard Time", "Europe/Stockholm", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Europe Standard Time", "Arctic/Longyearbyen", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Europe Standard Time", "Europe/San_Marino", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Europe Standard Time", "Europe/Vatican", FLB_TZ_UTC_OFFSET(1, 0) },
    { "Central Europe Standard Time", "Europe/Budapest", FLB_TZ_UTC_OFFSET(1, 0) },
    { "Central Europe Standard Time", "Europe/Tirane", FLB_TZ_UTC_OFFSET(1, 0) },
    { "Central Europe Standard Time", "Europe/Prague", FLB_TZ_UTC_OFFSET(1, 0) },
    { "Central Europe Standard Time", "Europe/Podgorica", FLB_TZ_UTC_OFFSET(1, 0) },
    { "Central Europe Standard Time", "Europe/Belgrade", FLB_TZ_UTC_OFFSET(1, 0) },
    { "Central Europe Standard Time", "Europe/Ljubljana", FLB_TZ_UTC_OFFSET(1, 0) },
    { "Central Europe Standard Time", "Europe/Bratislava", FLB_TZ_UTC_OFFSET(1, 0) },
    { "Romance Standard Time", "Europe/Paris", FLB_TZ_UTC_OFFSET(1, 0) },
    { "Romance Standard Time", "Europe/Brussels", FLB_TZ_UTC_OFFSET(1, 0) },
    { "Romance Standard Time", "Europe/Copenhagen", FLB_TZ_UTC_OFFSET(1, 0) },
    { "Romance Standard Time", "Africa/Ceuta", FLB_TZ_UTC_OFFSET(1, 0) },
    { "Central European Standard Time", "Europe/Warsaw", FLB_TZ_UTC_OFFSET(1, 0) },
    { "Central European Standard Time", "Europe/Sarajevo", FLB_TZ_UTC_OFFSET(1, 0) },
    { "Central European Standard Time", "Europe/Zagreb", FLB_TZ_UTC_OFFSET(1, 0) },
    { "Central European Standard Time", "Europe/Skopje", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Central Africa Standard Time", "Africa/Lagos", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Central Africa Standard Time", "Africa/Luanda", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Central Africa Standard Time", "Africa/Porto-Novo", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Central Africa Standard Time", "Africa/Kinshasa", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Central Africa Standard Time", "Africa/Bangui", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Central Africa Standard Time", "Africa/Brazzaville", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Central Africa Standard Time", "Africa/Douala", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Central Africa Standard Time", "Africa/Algiers", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Central Africa Standard Time", "Africa/Libreville", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Central Africa Standard Time", "Africa/Malabo", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Central Africa Standard Time", "Africa/Niamey", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Central Africa Standard Time", "Africa/Ndjamena", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Central Africa Standard Time", "Africa/Tunis", FLB_TZ_UTC_OFFSET(1, 0) },
    { "W. Central Africa Standard Time", "Etc/GMT-1", FLB_TZ_UTC_OFFSET(1, 0) },
    { "Jordan Standard Time", "Asia/Amman", FLB_TZ_UTC_OFFSET(2, 0) },
    { "GTB Standard Time", "Europe/Bucharest", FLB_TZ_UTC_OFFSET(2, 0) },
    { "GTB Standard Time", "Asia/Nicosia", FLB_TZ_UTC_OFFSET(2, 0) },
    { "GTB Standard Time", "Asia/Famagusta", FLB_TZ_UTC_OFFSET(2, 0) },
    { "GTB Standard Time", "Europe/Athens", FLB_TZ_UTC_OFFSET(2, 0) },
    { "Middle East Standard Time", "Asia/Beirut", FLB_TZ_UTC_OFFSET(2, 0) },
    { "Egypt Standard Time", "Africa/Cairo", FLB_TZ_UTC_OFFSET(2, 0) },
    { "E. Europe Standard Time", "Europe/Chisinau", FLB_TZ_UTC_OFFSET(2, 0) },
    { "Syria Standard Time", "Asia/Damascus", FLB_TZ_UTC_OFFSET(2, 0) },
    { "West Bank Standard Time", "Asia/Hebron", FLB_TZ_UTC_OFFSET(2, 0) },
    { "West Bank Standard Time", "Asia/Gaza", FLB_TZ_UTC_OFFSET(2, 0) },
    { "South Africa Standard Time", "Africa/Johannesburg", FLB_TZ_UTC_OFFSET(2, 0) },
    { "South Africa Standard Time", "Africa/Bujumbura", FLB_TZ_UTC_OFFSET(2, 0) },
    { "South Africa Standard Time", "Africa/Gaborone", FLB_TZ_UTC_OFFSET(2, 0) },
    { "South Africa Standard Time", "Africa/Lubumbashi", FLB_TZ_UTC_OFFSET(2, 0) },
    { "South Africa Standard Time", "Africa/Maseru", FLB_TZ_UTC_OFFSET(2, 0) },
    { "South Africa Standard Time", "Africa/Blantyre", FLB_TZ_UTC_OFFSET(2, 0) },
    { "South Africa Standard Time", "Africa/Maputo", FLB_TZ_UTC_OFFSET(2, 0) },
    { "South Africa Standard Time", "Africa/Kigali", FLB_TZ_UTC_OFFSET(2, 0) },
    { "South Africa Standard Time", "Africa/Mbabane", FLB_TZ_UTC_OFFSET(2, 0) },
    { "South Africa Standard Time", "Africa/Lusaka", FLB_TZ_UTC_OFFSET(2, 0) },
    { "South Africa Standard Time", "Africa/Harare", FLB_TZ_UTC_OFFSET(2, 0) },
    { "South Africa Standard Time", "Etc/GMT-2", FLB_TZ_UTC_OFFSET(2, 0) },
    { "FLE Standard Time", "Europe/Kyiv", FLB_TZ_UTC_OFFSET(2, 0) },
    { "FLE Standard Time", "Europe/Kiev", FLB_TZ_UTC_OFFSET(2, 0) },
    { "FLE Standard Time", "Europe/Mariehamn", FLB_TZ_UTC_OFFSET(2, 0) },
    { "FLE Standard Time", "Europe/Sofia", FLB_TZ_UTC_OFFSET(2, 0) },
    { "FLE Standard Time", "Europe/Tallinn", FLB_TZ_UTC_OFFSET(2, 0) },
    { "FLE Standard Time", "Europe/Helsinki", FLB_TZ_UTC_OFFSET(2, 0) },
    { "FLE Standard Time", "Europe/Vilnius", FLB_TZ_UTC_OFFSET(2, 0) },
    { "FLE Standard Time", "Europe/Riga", FLB_TZ_UTC_OFFSET(2, 0) },
    { "FLE Standard Time", "Europe/Uzhgorod", FLB_TZ_UTC_OFFSET(2, 0) },
    { "FLE Standard Time", "Europe/Zaporozhye", FLB_TZ_UTC_OFFSET(2, 0) },
    { "Israel Standard Time", "Asia/Jerusalem", FLB_TZ_UTC_OFFSET(2, 0) },
    { "South Sudan Standard Time", "Africa/Juba", FLB_TZ_UTC_OFFSET(2, 0) },
    { "Kaliningrad Standard Time", "Europe/Kaliningrad", FLB_TZ_UTC_OFFSET(2, 0) },
    { "Sudan Standard Time", "Africa/Khartoum", FLB_TZ_UTC_OFFSET(2, 0) },
    { "Libya Standard Time", "Africa/Tripoli", FLB_TZ_UTC_OFFSET(2, 0) },
    { "Namibia Standard Time", "Africa/Windhoek", FLB_TZ_UTC_OFFSET(2, 0) },
    { "Arabic Standard Time", "Asia/Baghdad", FLB_TZ_UTC_OFFSET(3, 0) },
    { "Turkey Standard Time", "Europe/Istanbul", FLB_TZ_UTC_OFFSET(3, 0) },
    { "Arab Standard Time", "Asia/Riyadh", FLB_TZ_UTC_OFFSET(3, 0) },
    { "Arab Standard Time", "Asia/Bahrain", FLB_TZ_UTC_OFFSET(3, 0) },
    { "Arab Standard Time", "Asia/Kuwait", FLB_TZ_UTC_OFFSET(3, 0) },
    { "Arab Standard Time", "Asia/Qatar", FLB_TZ_UTC_OFFSET(3, 0) },
    { "Arab Standard Time", "Asia/Aden", FLB_TZ_UTC_OFFSET(3, 0) },
    { "Belarus Standard Time", "Europe/Minsk", FLB_TZ_UTC_OFFSET(3, 0) },
    { "Russian Standard Time", "Europe/Moscow", FLB_TZ_UTC_OFFSET(3, 0) },
    { "Russian Standard Time", "Europe/Kirov", FLB_TZ_UTC_OFFSET(3, 0) },
    { "Russian Standard Time", "Europe/Simferopol", FLB_TZ_UTC_OFFSET(3, 0) },
    { "E. Africa Standard Time", "Africa/Nairobi", FLB_TZ_UTC_OFFSET(3, 0) },
    { "E. Africa Standard Time", "Antarctica/Syowa", FLB_TZ_UTC_OFFSET(3, 0) },
    { "E. Africa Standard Time", "Africa/Djibouti", FLB_TZ_UTC_OFFSET(3, 0) },
    { "E. Africa Standard Time", "Africa/Asmera", FLB_TZ_UTC_OFFSET(3, 0) },
    { "E. Africa Standard Time", "Africa/Addis_Ababa", FLB_TZ_UTC_OFFSET(3, 0) },
    { "E. Africa Standard Time", "Indian/Comoro", FLB_TZ_UTC_OFFSET(3, 0) },
    { "E. Africa Standard Time", "Indian/Antananarivo", FLB_TZ_UTC_OFFSET(3, 0) },
    { "E. Africa Standard Time", "Africa/Mogadishu", FLB_TZ_UTC_OFFSET(3, 0) },
    { "E. Africa Standard Time", "Africa/Dar_es_Salaam", FLB_TZ_UTC_OFFSET(3, 0) },
    { "E. Africa Standard Time", "Africa/Kampala", FLB_TZ_UTC_OFFSET(3, 0) },
    { "E. Africa Standard Time", "Indian/Mayotte", FLB_TZ_UTC_OFFSET(3, 0) },
    { "E. Africa Standard Time", "Etc/GMT-3", FLB_TZ_UTC_OFFSET(3, 0) },
    { "Iran Standard Time", "Asia/Tehran", FLB_TZ_UTC_OFFSET(3, 30) },
    { "Arabian Standard Time", "Asia/Dubai", FLB_TZ_UTC_OFFSET(4, 0) },
    { "Arabian Standard Time", "Asia/Muscat", FLB_TZ_UTC_OFFSET(4, 0) },
    { "Arabian Standard Time", "Etc/GMT-4", FLB_TZ_UTC_OFFSET(4, 0) },
    { "Astrakhan Standard Time", "Europe/Astrakhan", FLB_TZ_UTC_OFFSET(4, 0) },
    { "Astrakhan Standard Time", "Europe/Ulyanovsk", FLB_TZ_UTC_OFFSET(4, 0) },
    { "Azerbaijan Standard Time", "Asia/Baku", FLB_TZ_UTC_OFFSET(4, 0) },
    { "Russia Time Zone 3", "Europe/Samara", FLB_TZ_UTC_OFFSET(4, 0) },
    { "Mauritius Standard Time", "Indian/Mauritius", FLB_TZ_UTC_OFFSET(4, 0) },
    { "Mauritius Standard Time", "Indian/Reunion", FLB_TZ_UTC_OFFSET(4, 0) },
    { "Mauritius Standard Time", "Indian/Mahe", FLB_TZ_UTC_OFFSET(4, 0) },
    { "Saratov Standard Time", "Europe/Saratov", FLB_TZ_UTC_OFFSET(4, 0) },
    { "Georgian Standard Time", "Asia/Tbilisi", FLB_TZ_UTC_OFFSET(4, 0) },
    { "Volgograd Standard Time", "Europe/Volgograd", FLB_TZ_UTC_OFFSET(3, 0) },
    { "Caucasus Standard Time", "Asia/Yerevan", FLB_TZ_UTC_OFFSET(4, 0) },
    { "Afghanistan Standard Time", "Asia/Kabul", FLB_TZ_UTC_OFFSET(4, 30) },
    { "West Asia Standard Time", "Asia/Tashkent", FLB_TZ_UTC_OFFSET(5, 0) },
    { "West Asia Standard Time", "Antarctica/Mawson", FLB_TZ_UTC_OFFSET(5, 0) },
    { "West Asia Standard Time", "Asia/Oral", FLB_TZ_UTC_OFFSET(5, 0) },
    { "West Asia Standard Time", "Asia/Aqtau", FLB_TZ_UTC_OFFSET(5, 0) },
    { "West Asia Standard Time", "Asia/Aqtobe", FLB_TZ_UTC_OFFSET(5, 0) },
    { "West Asia Standard Time", "Asia/Atyrau", FLB_TZ_UTC_OFFSET(5, 0) },
    { "West Asia Standard Time", "Indian/Maldives", FLB_TZ_UTC_OFFSET(5, 0) },
    { "West Asia Standard Time", "Indian/Kerguelen", FLB_TZ_UTC_OFFSET(5, 0) },
    { "West Asia Standard Time", "Asia/Dushanbe", FLB_TZ_UTC_OFFSET(5, 0) },
    { "West Asia Standard Time", "Asia/Ashgabat", FLB_TZ_UTC_OFFSET(5, 0) },
    { "West Asia Standard Time", "Asia/Samarkand", FLB_TZ_UTC_OFFSET(5, 0) },
    { "West Asia Standard Time", "Etc/GMT-5", FLB_TZ_UTC_OFFSET(5, 0) },
    { "Ekaterinburg Standard Time", "Asia/Yekaterinburg", FLB_TZ_UTC_OFFSET(5, 0) },
    { "Pakistan Standard Time", "Asia/Karachi", FLB_TZ_UTC_OFFSET(5, 0) },
    { "Qyzylorda Standard Time", "Asia/Qyzylorda", FLB_TZ_UTC_OFFSET(5, 0) },
    { "India Standard Time", "Asia/Kolkata", FLB_TZ_UTC_OFFSET(5, 30) },
    { "India Standard Time", "Asia/Calcutta", FLB_TZ_UTC_OFFSET(5, 30) },
    { "Sri Lanka Standard Time", "Asia/Colombo", FLB_TZ_UTC_OFFSET(5, 30) },
    { "Nepal Standard Time", "Asia/Kathmandu", FLB_TZ_UTC_OFFSET(5, 45) },
    { "Nepal Standard Time", "Asia/Katmandu", FLB_TZ_UTC_OFFSET(5, 45) },
    { "Central Asia Standard Time", "Asia/Almaty", FLB_TZ_UTC_OFFSET(6, 0) },
    { "Central Asia Standard Time", "Antarctica/Vostok", FLB_TZ_UTC_OFFSET(6, 0) },
    { "Central Asia Standard Time", "Asia/Urumqi", FLB_TZ_UTC_OFFSET(6, 0) },
    { "Central Asia Standard Time", "Indian/Chagos", FLB_TZ_UTC_OFFSET(6, 0) },
    { "Central Asia Standard Time", "Asia/Bishkek", FLB_TZ_UTC_OFFSET(6, 0) },
    { "Central Asia Standard Time", "Asia/Qostanay", FLB_TZ_UTC_OFFSET(6, 0) },
    { "Central Asia Standard Time", "Etc/GMT-6", FLB_TZ_UTC_OFFSET(6, 0) },
    { "Bangladesh Standard Time", "Asia/Dhaka", FLB_TZ_UTC_OFFSET(6, 0) },
    { "Bangladesh Standard Time", "Asia/Thimphu", FLB_TZ_UTC_OFFSET(6, 0) },
    { "Omsk Standard Time", "Asia/Omsk", FLB_TZ_UTC_OFFSET(6, 0) },
    { "Myanmar Standard Time", "Asia/Yangon", FLB_TZ_UTC_OFFSET(6, 30) },
    { "Myanmar Standard Time", "Asia/Rangoon", FLB_TZ_UTC_OFFSET(6, 30) },
    { "Myanmar Standard Time", "Indian/Cocos", FLB_TZ_UTC_OFFSET(6, 30) },
    { "SE Asia Standard Time", "Asia/Bangkok", FLB_TZ_UTC_OFFSET(7, 0) },
    { "SE Asia Standard Time", "Antarctica/Davis", FLB_TZ_UTC_OFFSET(7, 0) },
    { "SE Asia Standard Time", "Indian/Christmas", FLB_TZ_UTC_OFFSET(7, 0) },
    { "SE Asia Standard Time", "Asia/Jakarta", FLB_TZ_UTC_OFFSET(7, 0) },
    { "SE Asia Standard Time", "Asia/Pontianak", FLB_TZ_UTC_OFFSET(7, 0) },
    { "SE Asia Standard Time", "Asia/Phnom_Penh", FLB_TZ_UTC_OFFSET(7, 0) },
    { "SE Asia Standard Time", "Asia/Vientiane", FLB_TZ_UTC_OFFSET(7, 0) },
    { "SE Asia Standard Time", "Asia/Ho_Chi_Minh", FLB_TZ_UTC_OFFSET(7, 0) },
    { "SE Asia Standard Time", "Asia/Saigon", FLB_TZ_UTC_OFFSET(7, 0) },
    { "SE Asia Standard Time", "Etc/GMT-7", FLB_TZ_UTC_OFFSET(7, 0) },
    { "Altai Standard Time", "Asia/Barnaul", FLB_TZ_UTC_OFFSET(7, 0) },
    { "W. Mongolia Standard Time", "Asia/Hovd", FLB_TZ_UTC_OFFSET(7, 0) },
    { "North Asia Standard Time", "Asia/Krasnoyarsk", FLB_TZ_UTC_OFFSET(7, 0) },
    { "North Asia Standard Time", "Asia/Novokuznetsk", FLB_TZ_UTC_OFFSET(7, 0) },
    { "N. Central Asia Standard Time", "Asia/Novosibirsk", FLB_TZ_UTC_OFFSET(7, 0) },
    { "Tomsk Standard Time", "Asia/Tomsk", FLB_TZ_UTC_OFFSET(7, 0) },
    { "China Standard Time", "Asia/Shanghai", FLB_TZ_UTC_OFFSET(8, 0) },
    { "China Standard Time", "Asia/Hong_Kong", FLB_TZ_UTC_OFFSET(8, 0) },
    { "China Standard Time", "Asia/Macau", FLB_TZ_UTC_OFFSET(8, 0) },
    { "North Asia East Standard Time", "Asia/Irkutsk", FLB_TZ_UTC_OFFSET(8, 0) },
    { "Singapore Standard Time", "Asia/Singapore", FLB_TZ_UTC_OFFSET(8, 0) },
    { "Singapore Standard Time", "Asia/Brunei", FLB_TZ_UTC_OFFSET(8, 0) },
    { "Singapore Standard Time", "Asia/Makassar", FLB_TZ_UTC_OFFSET(8, 0) },
    { "Singapore Standard Time", "Asia/Kuching", FLB_TZ_UTC_OFFSET(8, 0) },
    { "Singapore Standard Time", "Asia/Kuala_Lumpur", FLB_TZ_UTC_OFFSET(8, 0) },
    { "Singapore Standard Time", "Asia/Manila", FLB_TZ_UTC_OFFSET(8, 0) },
    { "Singapore Standard Time", "Etc/GMT-8", FLB_TZ_UTC_OFFSET(8, 0) },
    { "W. Australia Standard Time", "Australia/Perth", FLB_TZ_UTC_OFFSET(8, 0) },
    { "Taipei Standard Time", "Asia/Taipei", FLB_TZ_UTC_OFFSET(8, 0) },
    { "Ulaanbaatar Standard Time", "Asia/Ulaanbaatar", FLB_TZ_UTC_OFFSET(8, 0) },
    { "Ulaanbaatar Standard Time", "Asia/Choibalsan", FLB_TZ_UTC_OFFSET(8, 0) },
    { "Aus Central W. Standard Time", "Australia/Eucla", FLB_TZ_UTC_OFFSET(8, 45) },
    { "Transbaikal Standard Time", "Asia/Chita", FLB_TZ_UTC_OFFSET(9, 0) },
    { "Tokyo Standard Time", "Asia/Tokyo", FLB_TZ_UTC_OFFSET(9, 0) },
    { "Tokyo Standard Time", "Asia/Jayapura", FLB_TZ_UTC_OFFSET(9, 0) },
    { "Tokyo Standard Time", "Pacific/Palau", FLB_TZ_UTC_OFFSET(9, 0) },
    { "Tokyo Standard Time", "Asia/Dili", FLB_TZ_UTC_OFFSET(9, 0) },
    { "Tokyo Standard Time", "Etc/GMT-9", FLB_TZ_UTC_OFFSET(9, 0) },
    { "North Korea Standard Time", "Asia/Pyongyang", FLB_TZ_UTC_OFFSET(9, 0) },
    { "Korea Standard Time", "Asia/Seoul", FLB_TZ_UTC_OFFSET(9, 0) },
    { "Yakutsk Standard Time", "Asia/Yakutsk", FLB_TZ_UTC_OFFSET(9, 0) },
    { "Yakutsk Standard Time", "Asia/Khandyga", FLB_TZ_UTC_OFFSET(9, 0) },
    { "Cen. Australia Standard Time", "Australia/Adelaide", FLB_TZ_UTC_OFFSET(9, 30) },
    { "Cen. Australia Standard Time", "Australia/Broken_Hill", FLB_TZ_UTC_OFFSET(9, 30) },
    { "AUS Central Standard Time", "Australia/Darwin", FLB_TZ_UTC_OFFSET(9, 30) },
    { "E. Australia Standard Time", "Australia/Brisbane", FLB_TZ_UTC_OFFSET(10, 0) },
    { "E. Australia Standard Time", "Australia/Lindeman", FLB_TZ_UTC_OFFSET(10, 0) },
    { "AUS Eastern Standard Time", "Australia/Sydney", FLB_TZ_UTC_OFFSET(10, 0) },
    { "AUS Eastern Standard Time", "Australia/Melbourne", FLB_TZ_UTC_OFFSET(10, 0) },
    { "West Pacific Standard Time", "Pacific/Port_Moresby", FLB_TZ_UTC_OFFSET(10, 0) },
    { "West Pacific Standard Time", "Antarctica/DumontDUrville", FLB_TZ_UTC_OFFSET(10, 0) },
    { "West Pacific Standard Time", "Pacific/Truk", FLB_TZ_UTC_OFFSET(10, 0) },
    { "West Pacific Standard Time", "Pacific/Chuuk", FLB_TZ_UTC_OFFSET(10, 0) },
    { "West Pacific Standard Time", "Pacific/Guam", FLB_TZ_UTC_OFFSET(10, 0) },
    { "West Pacific Standard Time", "Pacific/Saipan", FLB_TZ_UTC_OFFSET(10, 0) },
    { "West Pacific Standard Time", "Etc/GMT-10", FLB_TZ_UTC_OFFSET(10, 0) },
    { "Tasmania Standard Time", "Australia/Hobart", FLB_TZ_UTC_OFFSET(10, 0) },
    { "Tasmania Standard Time", "Australia/Currie", FLB_TZ_UTC_OFFSET(10, 0) },
    { "Tasmania Standard Time", "Antarctica/Macquarie", FLB_TZ_UTC_OFFSET(10, 0) },
    { "Vladivostok Standard Time", "Asia/Vladivostok", FLB_TZ_UTC_OFFSET(10, 0) },
    { "Vladivostok Standard Time", "Asia/Ust-Nera", FLB_TZ_UTC_OFFSET(10, 0) },
    { "Lord Howe Standard Time", "Australia/Lord_Howe", FLB_TZ_UTC_OFFSET(10, 30) },
    { "Bougainville Standard Time", "Pacific/Bougainville", FLB_TZ_UTC_OFFSET(11, 0) },
    { "Russia Time Zone 10", "Asia/Srednekolymsk", FLB_TZ_UTC_OFFSET(11, 0) },
    { "Magadan Standard Time", "Asia/Magadan", FLB_TZ_UTC_OFFSET(11, 0) },
    { "Norfolk Standard Time", "Pacific/Norfolk", FLB_TZ_UTC_OFFSET(11, 0) },
    { "Sakhalin Standard Time", "Asia/Sakhalin", FLB_TZ_UTC_OFFSET(11, 0) },
    { "Central Pacific Standard Time", "Pacific/Guadalcanal", FLB_TZ_UTC_OFFSET(11, 0) },
    { "Central Pacific Standard Time", "Antarctica/Casey", FLB_TZ_UTC_OFFSET(11, 0) },
    { "Central Pacific Standard Time", "Pacific/Pohnpei", FLB_TZ_UTC_OFFSET(11, 0) },
    { "Central Pacific Standard Time", "Pacific/Ponape", FLB_TZ_UTC_OFFSET(11, 0) },
    { "Central Pacific Standard Time", "Pacific/Kosrae", FLB_TZ_UTC_OFFSET(11, 0) },
    { "Central Pacific Standard Time", "Pacific/Noumea", FLB_TZ_UTC_OFFSET(11, 0) },
    { "Central Pacific Standard Time", "Pacific/Efate", FLB_TZ_UTC_OFFSET(11, 0) },
    { "Central Pacific Standard Time", "Etc/GMT-11", FLB_TZ_UTC_OFFSET(11, 0) },
    { "Russia Time Zone 11", "Asia/Kamchatka", FLB_TZ_UTC_OFFSET(12, 0) },
    { "Russia Time Zone 11", "Asia/Anadyr", FLB_TZ_UTC_OFFSET(12, 0) },
    { "New Zealand Standard Time", "Pacific/Auckland", FLB_TZ_UTC_OFFSET(12, 0) },
    { "New Zealand Standard Time", "Antarctica/McMurdo", FLB_TZ_UTC_OFFSET(12, 0) },
    { "UTC+12", "Etc/GMT-12", FLB_TZ_UTC_OFFSET(12, 0) },
    { "UTC+12", "Pacific/Tarawa", FLB_TZ_UTC_OFFSET(12, 0) },
    { "UTC+12", "Pacific/Majuro", FLB_TZ_UTC_OFFSET(12, 0) },
    { "UTC+12", "Pacific/Kwajalein", FLB_TZ_UTC_OFFSET(12, 0) },
    { "UTC+12", "Pacific/Nauru", FLB_TZ_UTC_OFFSET(12, 0) },
    { "UTC+12", "Pacific/Funafuti", FLB_TZ_UTC_OFFSET(12, 0) },
    { "UTC+12", "Pacific/Wake", FLB_TZ_UTC_OFFSET(12, 0) },
    { "UTC+12", "Pacific/Wallis", FLB_TZ_UTC_OFFSET(12, 0) },
    { "Fiji Standard Time", "Pacific/Fiji", FLB_TZ_UTC_OFFSET(12, 0) },
    { "Chatham Islands Standard Time", "Pacific/Chatham", FLB_TZ_UTC_OFFSET(12, 45) },
    { "UTC+13", "Etc/GMT-13", FLB_TZ_UTC_OFFSET(13, 0) },
    { "UTC+13", "Pacific/Enderbury", FLB_TZ_UTC_OFFSET(13, 0) },
    { "UTC+13", "Pacific/Fakaofo", FLB_TZ_UTC_OFFSET(13, 0) },
    { "Tonga Standard Time", "Pacific/Tongatapu", FLB_TZ_UTC_OFFSET(13, 0) },
    { "Samoa Standard Time", "Pacific/Apia", FLB_TZ_UTC_OFFSET(13, 0) },
    { "Line Islands Standard Time", "Pacific/Kiritimati", FLB_TZ_UTC_OFFSET(14, 0) },
    { "Line Islands Standard Time", "Etc/GMT-14", FLB_TZ_UTC_OFFSET(14, 0) },
    { NULL, NULL, 0 }
};


static pthread_once_t flb_time_tz_once = PTHREAD_ONCE_INIT;

static size_t tz_by_windows_count = 0;
static size_t tz_by_iana_count = 0;

static const struct flb_time_tz_map *tz_by_windows[sizeof(windows_iana_timezones) / sizeof(windows_iana_timezones[0])];
static const struct flb_time_tz_map *tz_by_iana[sizeof(windows_iana_timezones) / sizeof(windows_iana_timezones[0])];

static int compare_windows(const void *a, const void *b)
{
    const struct flb_time_tz_map *entry_a = *(const struct flb_time_tz_map **)a;
    const struct flb_time_tz_map *entry_b = *(const struct flb_time_tz_map **)b;
    return strcasecmp(entry_a->windows, entry_b->windows);
}

static int compare_iana(const void *a, const void *b)
{
    const struct flb_time_tz_map *entry_a = *(const struct flb_time_tz_map **)a;
    const struct flb_time_tz_map *entry_b = *(const struct flb_time_tz_map **)b;
    return strcmp(entry_a->iana, entry_b->iana);
}

static int compare_search_windows(const void *key, const void *member)
{
    const char *windows_key = (const char *)key;
    const struct flb_time_tz_map *entry = *(const struct flb_time_tz_map **)member;
    return strcasecmp(windows_key, entry->windows);
}

static int compare_search_iana(const void *key, const void *member)
{
    const char *iana_key = (const char *)key;
    const struct flb_time_tz_map *entry = *(const struct flb_time_tz_map **)member;
    return strcmp(iana_key, entry->iana);
}

static void flb_time_tz_init(void)
{
    int i, j;
    int found;

    tz_by_windows_count = 0;
    tz_by_iana_count = 0;

    for (i = 0; windows_iana_timezones[i].windows != NULL; i++) {
        /* Add to Windows table if not already present (keeps the first/canonical entry) */
        found = 0;
        for (j = 0; j < tz_by_windows_count; j++) {
            if (strcasecmp(windows_iana_timezones[i].windows, tz_by_windows[j]->windows) == 0) {
                found = 1;
                break;
            }
        }
        if (!found) {
            tz_by_windows[tz_by_windows_count++] = &windows_iana_timezones[i];
        }

        /* IANA zones are unique in the table, so we just add all of them */
        tz_by_iana[tz_by_iana_count++] = &windows_iana_timezones[i];
    }

    /* Sort the arrays */
    qsort(tz_by_windows, tz_by_windows_count, sizeof(tz_by_windows[0]), compare_windows);
    qsort(tz_by_iana, tz_by_iana_count, sizeof(tz_by_iana[0]), compare_iana);
}

const char *flb_time_windows_zone_to_iana(const char *windows_zone)
{
    const struct flb_time_tz_map **res;

    if (windows_zone == NULL) {
        return NULL;
    }

    pthread_once(&flb_time_tz_once, flb_time_tz_init);

    res = bsearch(windows_zone, tz_by_windows, tz_by_windows_count,
                  sizeof(tz_by_windows[0]), compare_search_windows);
    if (res != NULL) {
        return (*res)->iana;
    }

    return NULL;
}

const char *flb_time_iana_zone_to_windows(const char *iana_zone)
{
    const struct flb_time_tz_map **res;

    if (iana_zone == NULL) {
        return NULL;
    }

    pthread_once(&flb_time_tz_once, flb_time_tz_init);

    res = bsearch(iana_zone, tz_by_iana, tz_by_iana_count,
                  sizeof(tz_by_iana[0]), compare_search_iana);
    if (res != NULL) {
        return (*res)->windows;
    }

    return NULL;
}

int flb_time_windows_zone_to_utc_offset(const char *windows_zone, long *offset)
{
    const struct flb_time_tz_map **res;

    if (windows_zone == NULL || offset == NULL) {
        return -1;
    }

    pthread_once(&flb_time_tz_once, flb_time_tz_init);

    res = bsearch(windows_zone, tz_by_windows, tz_by_windows_count,
                  sizeof(tz_by_windows[0]), compare_search_windows);
    if (res != NULL) {
        *offset = (*res)->utc_offset;
        return 0;
    }

    return -1;
}

int flb_time_iana_zone_to_utc_offset(const char *iana_zone, long *offset)
{
    const struct flb_time_tz_map **res;

    if (iana_zone == NULL || offset == NULL) {
        return -1;
    }

    pthread_once(&flb_time_tz_once, flb_time_tz_init);

    res = bsearch(iana_zone, tz_by_iana, tz_by_iana_count,
                  sizeof(tz_by_iana[0]), compare_search_iana);
    if (res != NULL) {
        *offset = (*res)->utc_offset;
        return 0;
    }

    return -1;
}
