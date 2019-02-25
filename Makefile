REBAR = ./rebar3

.PHONY: all dialyzer eunit clean distclean console

EUNIT_TEST_FLAGS ?=

ifdef TEST
EUNIT_TEST_FLAGS += --module=$(TEST)
unexport TEST
endif

all:
	$(REBAR) compile

doc:
	$(REBAR) doc

dialyzer:
	$(REBAR) dialyzer

eunit:
	$(REBAR) eunit $(EUNIT_TEST_FLAGS)

clean:
	rm -rf doc/*
	$(REBAR) clean

distclean: clean
	rm -rf _build

console:
	$(REBAR) shell

