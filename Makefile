
USE_UTF8=2
USE_AES=1
USE_SHA=1
USE_RSA=1
USE_JSON=1
USE_JOSE=1

P_USE_JOSE=$(USE_JOSE)
P_USE_JSON=$(USE_JSON)
P_USE_RSA=$(USE_RSA)
P_USE_AES=$(USE_AES)
P_USE_UTF8=$(USE_UTF8)
P_USE_SHA=$(USE_SHA)

JSDOCSTYLE=default
JSTEMPLATEDIR=tools/jsdoc/templates/$(JSDOCSTYLE)/
YUICOMPRESSOR=tools/yuicompress.jar
SOURCES= src/encoding.js

ifeq ($(USE_JSON),0)
  P_USE_JOSE=0
endif

ifeq ($(USE_UTF8),0)
  P_USE_JSON=0
  P_USE_JOSE=0
endif

ifeq ($(USE_SHA),0)
  P_USE_RSA=0
  P_USE_JOSE=0
endif

ifeq ($(USE_RSA),0)
  P_USE_JOSE=0
endif

ifeq ($(USE_AES),0)
  P_USE_JOSE=0
endif

ifneq ($(P_USE_SHA),0)
  SOURCES += src/hashing.js
endif

ifneq ($(P_USE_RSA),0)
  SOURCES += src/bn.js src/rsa.js
endif

ifneq ($(P_USE_AES),0)
  SOURCES += src/aes.js
endif

ifneq ($(P_USE_JOSE),0)
  SOURCES += src/jose.js
endif

ifneq ($(P_USE_JSON),0)
  SOURCES += src/djson.js
endif

ifneq ($(P_USE_UTF8),0)
  ifeq ($(P_USE_UTF8),1)
    SOURCES+= src/utf8.js
  else
    SOURCES+= src/utf8_fast.js
  endif
endif

.PHONY: all test doc src/*.js

all: djcl.js

djcl.js: $(SOURCES)
	cat $^ | java -jar $(YUICOMPRESSOR) --type js >djcl.js
#	cp $^ $@

doc:
	rm -fr doc
	mkdir doc
	tools/jsdoc/jsdoc.js src/*.js -d doc -t $(JSTEMPLATEDIR) --private

test: djcl.js
	node test/run_tests.js

tidy:
	find . -name '*~' -delete
	rm -f core.js core_*.js

clean: tidy
	rm -fr sjcl.js doc

