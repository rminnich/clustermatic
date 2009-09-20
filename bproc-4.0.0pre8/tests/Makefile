LINUX=/usr/src/linux
CFLAGS=-Wall -g -O2 -I../clients
LIBS=-L../clients -lbproc

# These are the repeating, performance counting stress testing
LIBTESTPROGS:=test-fork-move test-rfork \
       test-ping-pong test-ping-pong-child \
       test-child-stop-continue test-remote-child-stop-continue

MISCTESTS:=test-rfork-fork test-config

PROGS:=$(MISCTESTS) movetest rexectest cpumunch sidtest gidtest $(LIBTESTPROGS) ptrace1 ptrace2 tree-move ping-pong wait ptree

#iofw_iod iofw
all: $(PROGS)

clean:
	rm -f $(PROGS)
	rm -f *.o

# Stress tests

libtest.o: libtest.c
	gcc $(CFLAGS) -c libtest.c
libtest.a: libtest.o
	ar rcs libtest.a libtest.o

test-fork-move.o: test-fork-move.c
test-fork-move: test-fork-move.o libtest.a
	gcc $(FLAGS) -o $@ $< $(LIBS) -L. -ltest

test-rfork.o: test-rfork.c
test-rfork: test-rfork.o libtest.a
	gcc $(FLAGS) -o $@ $< $(LIBS) -L. -ltest

test-ping-pong.o: test-ping-pong.c
test-ping-pong: test-ping-pong.o libtest.a
	gcc $(FLAGS) -o $@ $< $(LIBS) -L. -ltest

test-ping-pong-child.o: test-ping-pong-child.c
test-ping-pong-child: test-ping-pong-child.o libtest.a
	gcc $(FLAGS) -o $@ $< $(LIBS) -L. -ltest

test-child-stop-continue.o: test-child-stop-continue.c
test-child-stop-continue: test-child-stop-continue.o libtest.a
	gcc $(FLAGS) -o $@ $< $(LIBS) -L. -ltest

test-remote-child-stop-continue.o: test-remote-child-stop-continue.c
test-remote-child-stop-continue: test-remote-child-stop-continue.o libtest.a
	gcc $(FLAGS) -o $@ $< $(LIBS) -L. -ltest

test-remote-fork-wait.o: test-remote-fork-wait.c
test-remote-fork-wait: test-remote-fork-wait.o libtest.a
	gcc $(FLAGS) -o $@ $< $(LIBS) -L. -ltest

#--- Other misc test programs.
test-rfork-fork.o: test-rfork-fork.c
test-rfork-fork: test-rfork-fork.o
	gcc $(FLAGS) -o $@ $< $(LIBS)

test-config.o: test-config.c
test-config: test-config.o
	gcc $(FLAGS) -o $@ $< $(LIBS)


movetest: movetest.c
	gcc $(CFLAGS) movetest.c -o movetest $(LIBS)
rexectest: rexectest.c
	gcc $(CFLAGS) rexectest.c -o rexectest $(LIBS)
cpumunch: cpumunch.c
	gcc $(CFLAGS) cpumunch.c -o cpumunch $(LIBS)
sidtest: sidtest.c
	gcc $(CFLAGS) sidtest.c -o sidtest $(LIBS)
gidtest: gidtest.c
	gcc $(CFLAGS) gidtest.c -o gidtest $(LIBS)

ptrace: ptrace.c
	gcc $(CFLAGS) -o $@ $< $(LIBS)

ptrace1: ptrace1.c
	gcc $(CFLAGS) -o $@ $< $(LIBS)

ptrace2: ptrace2.c
	gcc $(CFLAGS) -o $@ $<

tree-move: tree-move.c
	gcc $(CFLAGS) -o $@ $< $(LIBS)

ping-pong: ping-pong.c
	gcc $(CFLAGS) -o $@ $< $(LIBS)

wait: wait.c
	gcc $(CFLAGS) -o $@ $< $(LIBS)

treefork: treefork.c
	gcc $(CFLAGS) -o $@ $< $(LIBS)

rfork: rfork.c
	gcc $(CFLAGS) -o $@ $< $(LIBS)

execve: execve.c
	gcc $(CFLAGS) -o $@ $< $(LIBS)

vrfork: vrfork.c
	gcc $(CFLAGS) -o $@ $< $(LIBS)

kt: kt.c
	gcc $(CFLAGS) -o $@ $< $(LIBS)

movesimple: movesimple.c
	gcc $(CFLAGS) -o $@ $< $(LIBS)

movesimple2: movesimple2.c
	gcc $(CFLAGS) -o $@ $< $(LIBS)

idtest: idtest.c
	gcc $(CFLAGS) -o $@ $< $(LIBS)


bproc_test.o: bproc_test.c
pgid.o: pgid.c
ptree.o: ptree.c

pgid: pgid.o bproc_test.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

ptree: ptree.o bproc_test.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)
