/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#include "oci_logan.h"
#include "oci_logan_conf.h"

static const region_mapping_t region_mappings[] = {
    {"yny", "ap-chuncheon-1"},
    {"hyd", "ap-hyderabad-1"},
    {"mel", "ap-melbourne-1"},
    {"bom", "ap-mumbai-1"},
    {"kix", "ap-osaka-1"},
    {"icn", "ap-seoul-1"},
    {"syd", "ap-sydney-1"},
    {"nrt", "ap-tokyo-1"},
    {"yul", "ca-montreal-1"},
    {"yyz", "ca-toronto-1"},
    {"ams", "eu-amsterdam-1"},
    {"fra", "eu-frankfurt-1"},
    {"zrh", "eu-zurich-1"},
    {"jed", "me-jeddah-1"},
    {"dxb", "me-dubai-1"},
    {"gru", "sa-saopaulo-1"},
    {"cwl", "uk-cardiff-1"},
    {"lhr", "uk-london-1"},
    {"iad", "us-ashburn-1"},
    {"phx", "us-phoenix-1"},
    {"sjc", "us-sanjose-1"},
    {"vcp", "sa-vinhedo-1"},
    {"scl", "sa-santiago-1"},
    {"mtz", "il-jerusalem-1"},
    {"mrs", "eu-marseille-1"},
    {"sin", "ap-singapore-1"},
    {"auh", "me-abudhabi-1"},
    {"lin", "eu-milan-1"},
    {"arn", "eu-stockholm-1"},
    {"jnb", "af-johannesburg-1"},
    {"cdg", "eu-paris-1"},
    {"qro", "mx-queretaro-1"},
    {"mad", "eu-madrid-1"},
    {"ord", "us-chicago-1"},
    {"mty", "mx-monterrey-1"},
    {"aga", "us-saltlake-2"},
    {"bog", "sa-bogota-1"},
    {"vap", "sa-valparaiso-1"},
    {"xsp", "ap-singapore-2"},
    {"ruh", "me-riyadh-1"},
    {"lfi", "us-langley-1"},
    {"luf", "us-luke-1"},
    {"ric", "us-gov-ashburn-1"},
    {"pia", "us-gov-chicago-1"},
    {"tus", "us-gov-phoenix-1"},
    {"ltn", "uk-gov-london-1"},
    {"brs", "uk-gov-cardiff-1"},
    {"nja", "ap-chiyoda-1"},
    {"ukb", "ap-ibaraki-1"},
    {"mct", "me-dcc-muscat-1"},
    {"wga", "ap-dcc-canberra-1"},
    {"bgy", "eu-dcc-milan-1"},
    {"mxp", "eu-dcc-milan-2"},
    {"snn", "eu-dcc-dublin-2"},
    {"dtm", "eu-dcc-rating-2"},
    {"dus", "eu-dcc-rating-1"},
    {"ork", "eu-dcc-dublin-1"},
    {"dac", "ap-dcc-gazipur-1"},
    {"vll", "eu-madrid-2"},
    {"str", "eu-frankfurt-2"},
    {"beg", "eu-jovanovac-1"},
    {"doh", "me-dcc-doha-1"},
    {"ebb", "us-somerset-1"},
    {"ebl", "us-thames-1"},
    {"avz", "eu-dcc-zurich-1"},
    {"avf", "eu-crissier-1"},
    {"ahu", "me-abudhabi-3"},
    {"rba", "me-alain-1"},
    {"rkt", "me-abudhabi-2"},
    {"shj", "me-abudhabi-4"},
    {"dtz", "ap-seoul-2"},
    {"dln", "ap-suwon-1"},
    {"bno", "ap-chuncheon-2"},
    {NULL, NULL}
};

static const realm_mapping_t realm_mappings[] = {
    {"oc1", "oraclecloud.com"},
    {"oc2", "oraclegovcloud.com"},
    {"oc3", "oraclegovcloud.com"},
    {"oc4", "oraclegovcloud.uk"},
    {"oc8", "oraclecloud8.com"},
    {"oc9", "oraclecloud9.com"},
    {"oc10", "oraclecloud10.com"},
    {"oc14", "oraclecloud14.com"},
    {"oc15", "oraclecloud15.com"},
    {"oc19", "oraclecloud.eu"},
    {"oc20", "oraclecloud20.com"},
    {"oc21", "oraclecloud21.com"},
    {"oc23", "oraclecloud23.com"},
    {"oc24", "oraclecloud24.com"},
    {"oc26", "oraclecloud26.com"},
    {"oc29", "oraclecloud29.com"},
    {"oc35", "oraclecloud35.com"},
    {NULL, NULL}
};

/*
    ref--> github.com/oracle/oci-python-sdk/blob/ba91eb1a51b0c1a38603dec0373a33f9b9962f8a/src/oci/regions_definitions.py 
    still  it have to be updated depending on new oraclecloudXX
*/
static const region_realm_mapping_t region_realm_mappings[] = {
    {"ap-chuncheon-1", "oc1"},
    {"ap-hyderabad-1", "oc1"},
    {"ap-melbourne-1", "oc1"},
    {"ap-mumbai-1", "oc1"},
    {"ap-osaka-1", "oc1"},
    {"ap-seoul-1", "oc1"},
    {"ap-sydney-1", "oc1"},
    {"ap-tokyo-1", "oc1"},
    {"ca-montreal-1", "oc1"},
    {"ca-toronto-1", "oc1"},
    {"eu-amsterdam-1", "oc1"},
    {"eu-frankfurt-1", "oc1"},
    {"eu-zurich-1", "oc1"},
    {"me-jeddah-1", "oc1"},
    {"me-dubai-1", "oc1"},
    {"sa-saopaulo-1", "oc1"},
    {"uk-cardiff-1", "oc1"},
    {"uk-london-1", "oc1"},
    {"us-ashburn-1", "oc1"},
    {"us-phoenix-1", "oc1"},
    {"us-sanjose-1", "oc1"},
    {"sa-vinhedo-1", "oc1"},
    {"sa-santiago-1", "oc1"},
    {"il-jerusalem-1", "oc1"},
    {"eu-marseille-1", "oc1"},
    {"ap-singapore-1", "oc1"},
    {"me-abudhabi-1", "oc1"},
    {"eu-milan-1", "oc1"},
    {"eu-stockholm-1", "oc1"},
    {"af-johannesburg-1", "oc1"},
    {"eu-paris-1", "oc1"},
    {"mx-queretaro-1", "oc1"},
    {"eu-madrid-1", "oc1"},
    {"us-chicago-1", "oc1"},
    {"mx-monterrey-1", "oc1"},
    {"us-saltlake-2", "oc1"},
    {"sa-bogota-1", "oc1"},
    {"sa-valparaiso-1", "oc1"},
    {"ap-singapore-2", "oc1"},
    {"me-riyadh-1", "oc1"},
    {"us-langley-1", "oc2"},
    {"us-luke-1", "oc2"},
    {"us-gov-ashburn-1", "oc3"},
    {"us-gov-chicago-1", "oc3"},
    {"us-gov-phoenix-1", "oc3"},
    {"uk-gov-london-1", "oc4"},
    {"uk-gov-cardiff-1", "oc4"},
    {"ap-chiyoda-1", "oc8"},
    {"ap-ibaraki-1", "oc8"},
    {"me-dcc-muscat-1", "oc9"},
    {"ap-dcc-canberra-1", "oc10"},
    {"eu-dcc-milan-1", "oc14"},
    {"eu-dcc-milan-2", "oc14"},
    {"eu-dcc-dublin-2", "oc14"},
    {"eu-dcc-rating-2", "oc14"},
    {"eu-dcc-rating-1", "oc14"},
    {"eu-dcc-dublin-1", "oc14"},
    {"ap-dcc-gazipur-1", "oc15"},
    {"eu-madrid-2", "oc19"},
    {"eu-frankfurt-2", "oc19"},
    {"eu-jovanovac-1", "oc20"},
    {"me-dcc-doha-1", "oc21"},
    {"us-somerset-1", "oc23"},
    {"us-thames-1", "oc23"},
    {"eu-dcc-zurich-1", "oc24"},
    {"eu-crissier-1", "oc24"},
    {"me-abudhabi-3", "oc26"},
    {"me-alain-1", "oc26"},
    {"me-abudhabi-2", "oc29"},
    {"me-abudhabi-4", "oc29"},
    {"ap-seoul-2", "oc35"},
    {"ap-suwon-1", "oc35"},
    {"ap-chuncheon-2", "oc35"},
    {NULL, NULL}
};


static struct flb_hash_table *oci_timezone_hash = NULL;

static const char *oci_supported_timezones[] = {
    "africa/abidjan", "africa/accra", "africa/addis_ababa", "africa/algiers",
    "africa/asmara", "africa/asmera", "africa/bamako", "africa/bangui",
    "africa/banjul", "africa/bissau", "africa/blantyre", "africa/brazzaville",
    "africa/bujumbura", "africa/cairo", "africa/casablanca", "africa/ceuta",
    "africa/conakry", "africa/dakar", "africa/dar_es_salaam",
    "africa/djibouti",
    "africa/douala", "africa/el_aaiun", "africa/freetown", "africa/gaborone",
    "africa/harare", "africa/johannesburg", "africa/juba", "africa/kampala",
    "africa/khartoum", "africa/kigali", "africa/kinshasa", "africa/lagos",
    "africa/libreville", "africa/lome", "africa/luanda", "africa/lubumbashi",
    "africa/lusaka", "africa/malabo", "africa/maputo", "africa/maseru",
    "africa/mbabane", "africa/mogadishu", "africa/monrovia", "africa/nairobi",
    "africa/ndjamena", "africa/niamey", "africa/nouakchott",
    "africa/ouagadougou",
    "africa/porto-novo", "africa/sao_tome", "africa/timbuktu",
    "africa/tripoli",
    "africa/tunis", "africa/windhoek", "america/adak", "america/anchorage",
    "america/anguilla", "america/antigua", "america/araguaina",
    "america/argentina/buenos_aires",
    "america/argentina/catamarca", "america/argentina/comodrivadavia",
    "america/argentina/cordoba",
    "america/argentina/jujuy", "america/argentina/la_rioja",
    "america/argentina/mendoza",
    "america/argentina/rio_gallegos", "america/argentina/salta",
    "america/argentina/san_juan",
    "america/argentina/san_luis", "america/argentina/tucuman",
    "america/argentina/ushuaia",
    "america/aruba", "america/asuncion", "america/atikokan", "america/atka",
    "america/bahia", "america/bahia_banderas", "america/barbados",
    "america/belem",
    "america/belize", "america/blanc-sablon", "america/boa_vista",
    "america/bogota",
    "america/boise", "america/buenos_aires", "america/cambridge_bay",
    "america/campo_grande",
    "america/cancun", "america/caracas", "america/catamarca",
    "america/cayenne",
    "america/cayman", "america/chicago", "america/chihuahua",
    "america/coral_harbour",
    "america/cordoba", "america/costa_rica", "america/creston",
    "america/cuiaba",
    "america/curacao", "america/danmarkshavn", "america/dawson",
    "america/dawson_creek",
    "america/denver", "america/detroit", "america/dominica",
    "america/edmonton",
    "america/eirunepe", "america/el_salvador", "america/ensenada",
    "america/fort_wayne",
    "america/fortaleza", "america/glace_bay", "america/godthab",
    "america/goose_bay",
    "america/grand_turk", "america/grenada", "america/guadeloupe",
    "america/guatemala",
    "america/guayaquil", "america/guyana", "america/halifax",
    "america/havana",
    "america/hermosillo", "america/indiana/indianapolis",
    "america/indiana/knox",
    "america/indiana/marengo", "america/indiana/petersburg",
    "america/indiana/tell_city",
    "america/indiana/vevay", "america/indiana/vincennes",
    "america/indiana/winamac",
    "america/indianapolis", "america/inuvik", "america/iqaluit",
    "america/jamaica",
    "america/jujuy", "america/juneau", "america/kentucky/louisville",
    "america/kentucky/monticello",
    "america/knox_in", "america/kralendijk", "america/la_paz", "america/lima",
    "america/los_angeles", "america/louisville", "america/lower_princes",
    "america/maceio",
    "america/managua", "america/manaus", "america/marigot",
    "america/martinique",
    "america/matamoros", "america/mazatlan", "america/mendoza",
    "america/menominee",
    "america/merida", "america/metlakatla", "america/mexico_city",
    "america/miquelon",
    "america/moncton", "america/monterrey", "america/montevideo",
    "america/montreal",
    "america/montserrat", "america/nassau", "america/new_york",
    "america/nipigon",
    "america/nome", "america/noronha", "america/north_dakota/beulah",
    "america/north_dakota/center",
    "america/north_dakota/new_salem", "america/ojinaga", "america/panama",
    "america/pangnirtung",
    "america/paramaribo", "america/phoenix", "america/port-au-prince",
    "america/port_of_spain",
    "america/porto_acre", "america/porto_velho", "america/puerto_rico",
    "america/rainy_river",
    "america/rankin_inlet", "america/recife", "america/regina",
    "america/resolute",
    "america/rio_branco", "america/rosario", "america/santa_isabel",
    "america/santarem",
    "america/santiago", "america/santo_domingo", "america/sao_paulo",
    "america/scoresbysund",
    "america/shiprock", "america/sitka", "america/st_barthelemy",
    "america/st_johns",
    "america/st_kitts", "america/st_lucia", "america/st_thomas",
    "america/st_vincent",
    "america/swift_current", "america/tegucigalpa", "america/thule",
    "america/thunder_bay",
    "america/tijuana", "america/toronto", "america/tortola",
    "america/vancouver",
    "america/virgin", "america/whitehorse", "america/winnipeg",
    "america/yakutat",
    "america/yellowknife", "antarctica/casey", "antarctica/davis",
    "antarctica/dumontdurville",
    "antarctica/macquarie", "antarctica/mawson", "antarctica/mcmurdo",
    "antarctica/palmer",
    "antarctica/rothera", "antarctica/south_pole", "antarctica/syowa",
    "antarctica/troll",
    "antarctica/vostok", "arctic/longyearbyen", "asia/aden", "asia/almaty",
    "asia/amman", "asia/anadyr", "asia/aqtau", "asia/aqtobe", "asia/ashgabat",
    "asia/ashkhabad", "asia/baghdad", "asia/bahrain", "asia/baku",
    "asia/bangkok",
    "asia/beirut", "asia/bishkek", "asia/brunei", "asia/calcutta",
    "asia/chita",
    "asia/choibalsan", "asia/chongqing", "asia/chungking", "asia/colombo",
    "asia/dacca",
    "asia/damascus", "asia/dhaka", "asia/dili", "asia/dubai", "asia/dushanbe",
    "asia/gaza", "asia/harbin", "asia/hebron", "asia/ho_chi_minh",
    "asia/hong_kong",
    "asia/hovd", "asia/irkutsk", "asia/istanbul", "asia/jakarta",
    "asia/jayapura",
    "asia/jerusalem", "asia/kabul", "asia/kamchatka", "asia/karachi",
    "asia/kashgar",
    "asia/kathmandu", "asia/katmandu", "asia/khandyga", "asia/kolkata",
    "asia/krasnoyarsk",
    "asia/kuala_lumpur", "asia/kuching", "asia/kuwait", "asia/macao",
    "asia/macau",
    "asia/magadan", "asia/makassar", "asia/manila", "asia/muscat",
    "asia/nicosia",
    "asia/novokuznetsk", "asia/novosibirsk", "asia/omsk", "asia/oral",
    "asia/phnom_penh",
    "asia/pontianak", "asia/pyongyang", "asia/qatar", "asia/qyzylorda",
    "asia/rangoon",
    "asia/riyadh", "asia/riyadh87", "asia/riyadh88", "asia/riyadh89",
    "asia/saigon",
    "asia/sakhalin", "asia/samarkand", "asia/seoul", "asia/shanghai",
    "asia/singapore",
    "asia/srednekolymsk", "asia/taipei", "asia/tashkent", "asia/tbilisi",
    "asia/tehran",
    "asia/tel_aviv", "asia/thimbu", "asia/thimphu", "asia/tokyo",
    "asia/ujung_pandang",
    "asia/ulaanbaatar", "asia/ulan_bator", "asia/urumqi", "asia/ust-nera",
    "asia/vientiane",
    "asia/vladivostok", "asia/yakutsk", "asia/yekaterinburg", "asia/yerevan",
    "atlantic/azores",
    "atlantic/bermuda", "atlantic/canary", "atlantic/cape_verde",
    "atlantic/faeroe",
    "atlantic/faroe", "atlantic/jan_mayen", "atlantic/madeira",
    "atlantic/reykjavik",
    "atlantic/south_georgia", "atlantic/st_helena", "atlantic/stanley",
    "australia/act",
    "australia/adelaide", "australia/brisbane", "australia/broken_hill",
    "australia/canberra",
    "australia/currie", "australia/darwin", "australia/eucla",
    "australia/hobart",
    "australia/lhi", "australia/lindeman", "australia/lord_howe",
    "australia/melbourne",
    "australia/north", "australia/nsw", "australia/perth",
    "australia/queensland",
    "australia/south", "australia/sydney", "australia/tasmania",
    "australia/victoria",
    "australia/west", "australia/yancowinna", "brazil/acre",
    "brazil/denoronha",
    "brazil/east", "brazil/west", "canada/atlantic", "canada/central",
    "canada/east-saskatchewan",
    "canada/eastern", "canada/mountain", "canada/newfoundland",
    "canada/pacific",
    "canada/saskatchewan", "canada/yukon", "cet", "chile/continental",
    "chile/easterisland",
    "cst6cdt", "cuba", "eet", "egypt", "eire", "est", "est5edt", "etc/gmt",
    "etc/gmt0", "etc/greenwich", "etc/uct", "etc/universal", "etc/utc",
    "etc/zulu",
    "europe/amsterdam", "europe/andorra", "europe/athens", "europe/belfast",
    "europe/belgrade",
    "europe/berlin", "europe/bratislava", "europe/brussels",
    "europe/bucharest",
    "europe/budapest", "europe/busingen", "europe/chisinau",
    "europe/copenhagen",
    "europe/dublin", "europe/gibraltar", "europe/guernsey", "europe/helsinki",
    "europe/isle_of_man", "europe/istanbul", "europe/jersey",
    "europe/kaliningrad",
    "europe/kiev", "europe/lisbon", "europe/ljubljana", "europe/london",
    "europe/luxembourg",
    "europe/madrid", "europe/malta", "europe/mariehamn", "europe/minsk",
    "europe/monaco",
    "europe/moscow", "europe/nicosia", "europe/oslo", "europe/paris",
    "europe/podgorica",
    "europe/prague", "europe/riga", "europe/rome", "europe/samara",
    "europe/san_marino",
    "europe/sarajevo", "europe/simferopol", "europe/skopje", "europe/sofia",
    "europe/stockholm",
    "europe/tallinn", "europe/tirane", "europe/tiraspol", "europe/uzhgorod",
    "europe/vaduz",
    "europe/vatican", "europe/vienna", "europe/vilnius", "europe/volgograd",
    "europe/warsaw",
    "europe/zagreb", "europe/zaporozhye", "europe/zurich", "gb", "gb-eire",
    "gmt",
    "gmt0", "greenwich", "hongkong", "hst", "iceland", "indian/antananarivo",
    "indian/chagos", "indian/christmas", "indian/cocos", "indian/comoro",
    "indian/kerguelen",
    "indian/mahe", "indian/maldives", "indian/mauritius", "indian/mayotte",
    "indian/reunion",
    "iran", "israel", "jamaica", "japan", "jst", "kwajalein", "libya", "met",
    "mexico/bajanorte", "mexico/bajasur", "mexico/general",
    "mideast/riyadh87",
    "mideast/riyadh88", "mideast/riyadh89", "mst", "mst7mdt", "navajo", "nz",
    "nz-chat",
    "pacific/apia", "pacific/auckland", "pacific/bougainville",
    "pacific/chatham",
    "pacific/chuuk", "pacific/easter", "pacific/efate", "pacific/enderbury",
    "pacific/fakaofo",
    "pacific/fiji", "pacific/funafuti", "pacific/galapagos",
    "pacific/gambier",
    "pacific/guadalcanal", "pacific/guam", "pacific/honolulu",
    "pacific/johnston",
    "pacific/kiritimati", "pacific/kosrae", "pacific/kwajalein",
    "pacific/majuro",
    "pacific/marquesas", "pacific/midway", "pacific/nauru", "pacific/niue",
    "pacific/norfolk",
    "pacific/noumea", "pacific/pago_pago", "pacific/palau",
    "pacific/pitcairn",
    "pacific/pohnpei", "pacific/ponape", "pacific/port_moresby",
    "pacific/rarotonga",
    "pacific/saipan", "pacific/samoa", "pacific/tahiti", "pacific/tarawa",
    "pacific/tongatapu",
    "pacific/truk", "pacific/wake", "pacific/wallis", "pacific/yap", "poland",
    "portugal",
    "prc", "pst", "pst8pdt", "rok", "singapore", "systemv/ast4",
    "systemv/ast4adt",
    "systemv/cst6", "systemv/cst6cdt", "systemv/est5", "systemv/est5edt",
    "systemv/hst10",
    "systemv/mst7", "systemv/mst7mdt", "systemv/pst8", "systemv/pst8pdt",
    "systemv/yst9",
    "systemv/yst9ydt", "turkey", "uct", "universal", "us/alaska",
    "us/aleutian",
    "us/arizona", "us/central", "us/east-indiana", "us/eastern", "us/hawaii",
    "us/indiana-starke", "us/michigan", "us/mountain", "us/pacific",
    "us/pacific-new",
    "us/samoa", "utc", "w-su", "wet", "zulu",
    NULL
};

static int init_oci_timezone_hash(void)
{
    int i;
    int ret;

    if (oci_timezone_hash != NULL) {
        return 0;
    }

    oci_timezone_hash =
        flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 1024, -1);
    if (!oci_timezone_hash) {
        return -2;
    }


    for (i = 0; oci_supported_timezones[i] != NULL; i++) {
        ret = flb_hash_table_add(oci_timezone_hash,
                                 oci_supported_timezones[i],
                                 strlen(oci_supported_timezones[i]),
                                 (void *) "1", sizeof("1"));
        if (ret < 0) {
            flb_hash_table_destroy(oci_timezone_hash);
            oci_timezone_hash = NULL;
            return -3;
        }
    }

    return 0;
}

static void cleanup_oci_timezone_hash(void)
{
    if (oci_timezone_hash) {
        flb_hash_table_destroy(oci_timezone_hash);
        oci_timezone_hash = NULL;
    }
}

static int is_oci_supported_timezone(const char *log_timezone)
{
    void *out_buf = NULL;
    size_t out_size = 0;
    char *lower_tz;
    int i, ht_ret;
    int ret_init_oci_timezone_hash;

    if (!log_timezone) {
        return 0;
    }
    ret_init_oci_timezone_hash = init_oci_timezone_hash();

    if (ret_init_oci_timezone_hash != 0) {
        return 0;
    }
    lower_tz = strdup(log_timezone);
    if (!lower_tz) {
        return 0;
    }

    for (i = 0; lower_tz[i]; i++) {
        lower_tz[i] = tolower(lower_tz[i]);
    }

    ht_ret = flb_hash_table_get(oci_timezone_hash, lower_tz, strlen(lower_tz),
                                &out_buf, &out_size);
    if (ht_ret < 0) {
        free(lower_tz);
        return 0;
    }
    free(lower_tz);
    return (out_buf != NULL && strcmp((char *) out_buf, "1") == 0) ? 1 : 0;
}


int is_valid_timezone(const char *log_timezone)
{

    if (!log_timezone || strlen(log_timezone) == 0) {
        return 0;
    }
    if (is_oci_supported_timezone(log_timezone)) {
        return 1;
    }
    return 0;
}

/* Determine the oracle cloud realm code based on region */
const char *determine_realm_from_region(const char *region)
{
    int i;

    if (!region) {
        return "oc1";
    }
    for (i = 0; region_realm_mappings[i].region != NULL; i++) {
        if (strcmp(region, region_realm_mappings[i].region) == 0) {
            return region_realm_mappings[i].realm;
        }
    }
    return "oc1";
}

/* gets the domain suffix for a specific oracle cloud realm */
const char *get_domain_suffix_for_realm(const char *realm)
{
    int i;

    if (!realm) {
        return "oraclecloud.com";
    }
    for (i = 0; realm_mappings[i].realm_code != NULL; i++) {
        if (strcmp(realm, realm_mappings[i].realm_code) == 0) {
            return realm_mappings[i].domain_suffix;
        }
    }

    return "oraclecloud.com";
}



const char *long_region_name(char *short_region_name)
{
    size_t i;

    if (short_region_name == NULL) {
        return NULL;
    }
    for (i = 0; i < COUNT_OF_REGION; i++) {
        if (strcmp(short_region_name, region_mappings[i].short_name) == 0) {
            return (region_mappings[i].long_name);
        }
    }
    return NULL;
}
