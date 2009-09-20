#
# Erik Hendriks <erik@hendriks.cx
#
# $Id: Makefile,v 1.24 2004/09/28 18:58:44 mkdist Exp $
.SUFFIXES: .1 .2 .8 .html .ps .tex .fig .eps .pdf

include ../Makefile.conf

.fig.eps:
	fig2dev -L eps $^ $@
.fig.pdf:
	fig2dev -L pdf $^ $@

FIGURES:=ptree.fig daemons.fig fork.fig

all:

clean:
# Cleanup after latex and friends
	rm -f *.dvi *.aux *.inx *.log *.ps *.eps *.pdf
	rm -f *.bbl *.blg *.idx *.ilg *.ind
	rm -f *~
	rm -rf bproc_ref

install: $(MANPAGES)
	for sec in 1 2 3 5 8 ; do \
	    mkdir -p $(prefix)$(mandir)/man$$sec || exit 1; \
	    for page in *.$$sec ; do \
	       install -m 644 $$page $(prefix)$(mandir)/man$$sec/$$page && \
	           gzip -f9 $(prefix)$(mandir)/man$$sec/$$page || \
	           exit 1; \
	    done ; \
	done

bproc_ref.ind: bproc_ref.tex conf.tex overview.tex procacct.tex messages.tex $(TEXPAGES) $(FIGURES:%.fig=%.eps)
	latex bproc_ref
	makeindex bproc_ref

bproc_ref.dvi: bproc_ref.tex conf.tex overview.tex procacct.tex messages.tex $(TEXPAGES) $(FIGURES:%.fig=%.eps) bproc_ref.ind 
	latex bproc_ref
	latex bproc_ref

bproc_ref/bproc_ref.html: bproc_ref.tex conf.tex overview.tex procacct.tex messages.tex $(TEXPAGES) $(FIGURES:%.fig=%.eps) bproc_ref.ind
	latex2html -transparent -white -antialias -antialias_text -split 4 bproc_ref

# This will probably get sucked into the big reference document at some point.
#messages.ind: messages.tex
#	latex messages
#	makeindex messages
#
#messages.dvi: messages.tex messages.ind
#	latex messages
#	latex messages

#ref.tex: $(TEXPAGES)
#	(echo '\documentclass{article}' ; \
#	 echo '\begin{document}' ; \
#	 echo '\title{BProc Reference Manual}' ; \
#	 cat $(TEXPAGES) ;\
#	 echo '\end{document}') > ref.tex
#ref.dvi: ref.tex
#	latex ref
#	latex ref
