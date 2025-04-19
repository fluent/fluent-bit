# mruby is using Rake (https://ruby.github.io/rake/) as a build tool.

RAKE = rake

all :
	$(RAKE)
.PHONY : all

test : all
	$(RAKE) test
.PHONY : test

clean :
	$(RAKE) clean
.PHONY : clean

check :
	pre-commit run --all-files
.PHONY : check

checkinstall :
	pre-commit install
.PHONY : checkinstall

checkupdate :
	pre-commit autoupdate
.PHONY : checkupdate

composecheck :
	docker-compose -p mruby run test pre-commit run --all-files
.PHONY : composecheck

composetest :
	docker-compose -p mruby run test
.PHONY : composetest
