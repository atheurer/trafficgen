#!/bin/bash

force_install=0

opts=$(getopt -q -o -c: --longoptions "force" -n "getopt.sh" -- "$@")
if [ $? -ne 0 ]; then
    printf -- "$*\n"
    printf -- "\n"
    printf -- "\tThe following options are available:\n\n"
    printf -- "\n"
    printf -- "--force\n"
    printf -- "  Download and build MoonGen even if it is already present.\n"
    exit 1
fi
eval set -- "$opts"
while true; do
    case "${1}" in
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

tg_dir=$(dirname $0)

moongen_url="https://github.com/emmericp/MoonGen.git"
moongen_dir="MoonGen"

if pushd ${tg_dir} > /dev/null; then
    if [ -d ${moongen_dir} -a "${force_install}" == "0" ]; then
	echo "MoonGen already installed"
    else
	if [ -d ${moongen_dir} ]; then
	    /bin/rm -Rf ${moongen_dir}
	fi

	git clone ${moongen_url}

	if pushd ${moongen_dir} > /dev/null; then
	    # pick a tested MoonGen version/commit
	    git checkout 525d9917c98a4760db72bb733cf6ad30550d6669

	    # manually initialize the libmoon submodule so we can tweak it
	    git submodule update --init

	    # disable the auto device binding, we don't want that to happen
	    head -n -5 libmoon/build.sh > libmoon/foo
	    echo ")" >> libmoon/foo
	    chmod +x libmoon/foo
	    mv libmoon/foo libmoon/build.sh

	    # build MoonGen
	    ./build.sh

	    popd > /dev/null
	else
	    echo "ERROR: Could not find MoonGen directory"
	    exit 1
	fi
    fi	

    popd > /dev/null
else
    echo "ERROR: Could not find trafficgen directory!"
    exit 1
fi

exit 0
