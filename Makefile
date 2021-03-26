auxv: auxv.c
	#${CC} -lcap -o $@ $<
	${CC} -g -o $@ $<

cap: cap.c
	${CC} -lcap -g -o $@ $<
