#!/bin/bash

full_script_path=$(readlink -e ${0})
tgen_dir=$(dirname ${full_script_path})

base_dir="/opt/trex"
tmp_dir="/tmp"
trex_ver="v2.87"
insecure_curl=0
force_install=0
toolbox_url=https://github.com/perftool-incubator/toolbox.git

opts=$(getopt -q -o c: --longoptions "tmp-dir:,base-dir:,version:,insecure,force" -n "getopt.sh" -- "$@")
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
    printf -- "\n"
    printf -- "--insecure\n"
    printf -- "  Disable SSL cert verification for the TRex download site.\n"
    printf -- "  Some environments require this due to the usage of an uncommon CA.\n"
    printf -- "  Do not use this option if you do not understand the implications.\n"
    printf -- "\n"
    printf -- "--force\n"
    printf -- "  Download and install TRex even if it is already present.\n"
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
	--insecure)
	    shift
	    insecure_curl=1
	    ;;
	--force)
	    shift
	    force_install=1
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

if [ -d ${trex_dir} -a "${force_install}" == "0" ]; then
    echo "TRex ${trex_ver} already installed"
else
    if [ -d ${trex_dir} ]; then
	/bin/rm -Rf ${trex_dir}
    fi

    mkdir -p ${base_dir}
    if pushd ${base_dir} >/dev/null; then
	tarfile="${tmp_dir}/${trex_ver}.tar.gz"
	/bin/rm -f ${tarfile}
	curl_args=""
	if [ "${insecure_curl}" == "1" ]; then
	    curl_args="-k"
	fi
	echo "Downloading TRex ${trex_ver} from ${trex_url}..."
	curl ${curl_args} --silent --output ${tarfile} ${trex_url}
	curl_rc=$?
	if [ "${curl_rc}" == "0" ]; then
	    if tar zxf ${tarfile}; then
		/bin/rm ${tarfile}
		echo "installed TRex ${trex_ver} from ${trex_url}"
	    else
		echo "ERROR: could not unpack ${tarfile} for TRex ${trex_ver}"
		exit 1
	    fi
	else
	    if [ "${curl_rc}" == "60" ]; then
		echo "ERROR: SSL certificate failed validation on TRex download.  Run --help and see --insecure option"
		exit 1
	    else
		echo "ERROR: TRex download failed (curl return code is ${curl_rc})"
		exit 1
	    fi
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

if [ ! -d ${tgen_dir}/toolbox ]; then
    if pushd ${tgen_dir} > /dev/null; then
        echo "Installing toolbox..."
        git clone ${toolbox_url}

        popd > /dev/null
    fi
else
    if pushd ${tgen_dir}/toolbox > /dev/null; then
        echo "Updating toolbox..."
        git fetch --all
        git pull --ff-only

        popd > /dev/null
    fi
fi
