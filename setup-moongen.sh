#!/bin/bash

NUM_CPUS=$(cat /proc/cpuinfo  | grep "processor\\s: " | wc -l)

if git submodule init && git submodule update; then
	if pushd MoonGen; then
		git submodule update --init --recursive
		if pushd libmoon/deps/luajit; then
			if make -j $NUM_CPUS BUILDMODE=static 'CFLAGS=-DLUAJIT_NUMMODE=2 -DLUAJIT_ENABLE_LUA52COMPAT'; then
				if make install DESTDIR=$(pwd); then
					popd 
				else
					echo "make-install of luajit failed, exiting"
					exit 3
				fi
			else
				echo "make of luajit failed, exiting"
				exit 2
		fi
		else
			echo "Could not find libmoon/deps/luajit, exiting"
			exit 1
		fi


		if pushd libmoon/deps/dpdk; then
			sed -i -e 's@SRCS-y += ethtool/igb/igb_main.c@#SRCS-y += ethtool/igb/igb_main.c/@' lib/librte_eal/linuxapp/kni/Makefile
			if make -j $NUM_CPUS install T=x86_64-native-linuxapp-gcc DESTDIR=install; then
				popd 
			else
				echo "make-install of dpdk failed, exiting"
				exit 5
			fi
		else
			echo "Could not find libmoon/deps/dpdk, exiting"
			exit 4
		fi
	
		if pushd build; then
			if cmake .. && make -j $NUM_CPUS; then
				popd
			else
				echo "Build of MoonGen failed, exiting" && exit 7
			fi
		else
				echo "Could not find ./build, exiting" && exit 6
		fi
    	popd
	fi
else
	echo "Could not git submodule"
fi
