DEPS= $(wildcard *.m4i)
M4= $(patsubst %.m4,%.spthy,$(wildcard *.m4))
PROOFS= $(patsubst %.m4,%.proof,$(wildcard *.m4))

ifdef ALLOW_FALSIFICATION
ARGS += -a
endif

all: proofs

proofs: $(PROOFS)

clean:
	rm -f $(M4)

%.spthy: %.m4 $(DEPS)
	m4 $(FLAGS) -I. $< > $@

%.proof: %.spthy
	python ./run-tamarin.py $(ARGS) $<
