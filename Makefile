auxv: auxv.c
	${CC} -g -o $@ $<

cap-sta: cap.c
	${CC} -o $@ $< -Wl,-Bstatic -lcap -Wl,-Bdynamic

cap-dyn: cap.c
	${CC} -lcap -g -o $@ $<
