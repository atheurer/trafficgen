#!/bin/bash

base_dir="/opt/trex"
tmp_dir="/tmp"
trex_ver="v2.53"

opts=$(getopt -q -o c: --longoptions "tmp-dir:,base-dir:,version:" -n "getopt.sh" -- "$@")
if [ $? -ne 0 ]; then
    printf -- "$*\n"
    printf -- "\n"
    printf -- "\tThe following options are available:\n\n"
    printf -- "\n"
    printf -- "--tmp-dir=str\n"
    printf -- "  Directory where temporary files should be stored.\n"
    printf -- "  Default is ${tmp_dir}\n"
    printf -- "\n"
    printf -- "--base-dir=str\n"
    printf -- "  Directory where TRex will be installed.\n"
    printf -- "  Default is ${base_dir}\n"
    printf -- "\n"
    printf -- "--version=str\n"
    printf -- "  Version of TRex to install\n"
    printf -- "  Default is ${trex_ver}\n"
    exit 1
fi
eval set -- "$opts"
while true; do
    case "${1}" in
	--tmp-dir)
	    shift
	    if [ -n "${1}" ]; then
		tmp_dir=${1}
		shift
	    fi
	    ;;
	--base-dir)
	    shift
	    if [ -n "${1}" ]; then
		base_dir=${1}
		shift
	    fi
	    ;;
	--version)
	    shift
	    if [ -n "${1}" ]; then
		trex_ver=${1}
		shift
	    fi
	    ;;
	--)
	    break
	    ;;
	*)
	    if [ -n "${1}" ]; then
		echo "ERROR: Unrecognized option ${1}"
	    fi
	    exit 1
	    ;;
    esac
done

trex_url=https://trex-tgn.cisco.com/trex/release/${trex_ver}.tar.gz
trex_dir="${base_dir}/${trex_ver}"

if [ -d ${trex_dir} ]; then
    echo "TRex ${trex_ver} already installed"
else
    mkdir -p ${base_dir}
    if pushd ${base_dir} >/dev/null; then
	tarfile="${tmp_dir}/${trex_ver}.tar.gz"
	/bin/rm -f ${tarfile}
	if curl --output ${tarfile} ${trex_url} && tar zxf ${tarfile}; then
	    /bin/rm ${tarfile}
	    echo "installed TRex from ${trex_url}"
	else
	    echo "ERROR: could not install TRex ${trex_ver}"
	    exit 1
	fi
	popd >/dev/null
    else
	echo "ERROR: Could not use ${base_dir}"
	exit 1
    fi
fi

# we need a symlink so our trex scripts can always point to
# same location for trex
if pushd ${base_dir} >/dev/null; then
    /bin/rm -f current 2>/dev/null
    ln -sf ${trex_ver} current
    popd >/dev/null
fi

