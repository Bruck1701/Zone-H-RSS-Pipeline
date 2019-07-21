#!/bin/bash
for file in ./tmp/*
do
  	echo "Processing file $file"
	##python2 sfcli.py -u 192.168.12.101:5001 -e "$file"
	python2 sfcli.py -s http://192.168.12.101:5001 -e  "$file"
	sleep 5m
done
