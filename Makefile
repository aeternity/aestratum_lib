REBAR = ./rebar3

.PHONY: all dialyzer eunit clean distclean console

all:
	$(REBAR) compile

doc:
	$(REBAR) doc

dialyzer:
	$(REBAR) dialyzer

eunit:
	$(REBAR) eunit

clean:
	rm -rf doc/*
	$(REBAR) clean

distclean: clean
	rm -rf _build

console:
	$(REBAR) shell

