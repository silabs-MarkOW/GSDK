#! /bin/bash

function md5sum_tree
{
    find . -type f -exec md5sum '{}' ';' | sort | md5sum
}

STATUS=NONE
for dir in $*
do
    if ! test -d ${dir}
    then
	STATUS=NOTDIR
	break
    fi
    ( cd ${dir} ; echo ${dir} `md5sum_tree` )
    if test $? -ne 0
    then
	STATUS=FAIL
	break
    else
	STATUS=OK
    fi
done

if ! test "OK" = "${STATUS}"
then
    echo "Usage: md3tree folder [ [ folder ] ... ]"
fi
