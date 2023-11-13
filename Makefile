default :
	echo There is no default behavior

install :
	if ! test -z "${BINDIR}" ; then install -m 755 md5tree.sh ${BINDIR}/md5tree ; else echo "Usage: make BINDIR=... install" ; fi
