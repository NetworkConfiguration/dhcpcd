# Sample exit hook to lookup the hostname in DNS if not set

lookup_hostname()
{
	local h=
	# Silly ISC programs love to send error text to stdout
	if type dig >/dev/null 2>&1; then
		h=`dig +short -x ${new_ip_address}`
		if [ $? = 0 ]; then
			echo "${h}" | sed 's/\.$//'
			return 0
		fi
	elif type host >/dev/null 2>&1; then
		h=`host ${new_ip_address}`
		if [ $? = 0 ]; then 
			echo "${h}" \
			| sed 's/.* domain name pointer \(.*\)./\1/'
			return 0
		fi
	fi
	return 1
}

do_hostname()
{
	if [ -z "${new_host_name}" ] && need_hostname; then
		local hname="$(lookup_hostname)"
		if [ -n "${hname}" ]; then
			hostname "${hname}"
		fi
	fi
}

case "${reason}" in
	TEST)
		;;
	BOUND|INFORM|REBIND|REBOOT|RENEW|TIMEOUT)
		do_hostname
		;;
	EXPIRE|FAIL|IPV4LL|RELEASE|STOP)
		;;
	*)
		echo "lookup_hostname: unsupported reason ${reason}" >&2
		false
		;;
esac
