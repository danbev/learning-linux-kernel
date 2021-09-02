auxv: auxv.c
	${CC} -g -o $@ $<

cap-sta: cap.c
	${CC} -o $@ -Wl,-Bstatic -Wl,--whole-archive -lcap -Wl,--no-whole-archive -Wl,-Bdynamic $<

cap-dyn: cap.c
	${CC} -lcap -g -o $@ $<

getcap: getcap.c
	${CC} -Wall -Werror=sign-compare -g -o $@ $<

getcap_syscall: getcap_syscall.c
	${CC} -Wall -Werror=sign-compare -g -o $@ $<
