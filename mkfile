</$objtype/mkfile

MAN=/sys/man/1
BIN=/$objtype/bin
TARG=\
	catphone

OFILES=\
	main.$O\
	alloc.$O\
	sip.$O\

HFILES=\
	dat.h\
	fns.h\

</sys/src/cmd/mkone

install:V: man

uninstall:V:
	for(i in $TARG){
		rm -f $BIN/$i
		rm -f $MAN/$i
	}
