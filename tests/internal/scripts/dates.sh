# UTC
export TZ='UTC'
str=`date "+%m/%d/%Y %H:%M:%S %z"`
ts=`date "+%s"`

echo "UTC => $str, $ts"

# IST
export TZ='Asia/Kolkata'
str=`date "+%m/%d/%Y %H:%M:%S %z"`
ts=`date "+%s"`

echo "IST => $str, $ts"


# Japan
export TZ='Japan'
str=`date "+%m/%d/%Y %H:%M:%S %z"`
ts=`date "+%s"`

echo "JP  => $str, $ts"

# Africa/Harare
export TZ='Africa/Harare'
str=`date "+%m/%d/%Y %H:%M:%S %z"`
ts=`date "+%s"`

echo "ZW  => $str, $ts"
