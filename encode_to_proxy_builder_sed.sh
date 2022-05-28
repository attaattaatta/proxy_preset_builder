#!/bin/bash
# enable debug
#set -x -v

# $1 - ispmanager web server config input file
if [[ $# -eq 1 ]]
then
	RANDOM_N=$RANDOM
	INPUT_F=/tmp/sepd_RANDOM_N
	\cp -Rfp $1 $INPUT_F
	\sed -i 's@\"@\\\"@gi' $INPUT_F
	\sed -i 's/\@/\\@/gi' $INPUT_F
	\sed -i 's@\]@\\\]@gi' $INPUT_F
	\sed -i 's@\[@\\\[@gi' $INPUT_F
	\sed -i -E 's@(\.[^*+])@\\\\\\\1@gi' $INPUT_F
	\sed -i 's@\$@\\\\\\\$@gi' $INPUT_F
	\sed -i 's@{@\\{@gi' $INPUT_F
	\sed -i 's@}@\\}@gi' $INPUT_F
	\sed -i 's@(@\\(@gi' $INPUT_F
	\sed -i 's@)@\\)@gi' $INPUT_F
	\sed -i ':a;N;$!ba;s/\n/\\n/gi' $INPUT_F
	\sed -i 's@\t@\\t@gi' $INPUT_F
	\cat $INPUT_F
	\rm -f $INPUT_F
else
        printf "1 argument need\n"
        exit 1
fi
