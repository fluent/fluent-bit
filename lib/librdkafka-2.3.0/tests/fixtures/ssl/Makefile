ssl_keys: clear_keys
	@./create_keys.sh client client2

clear_keys:
	@rm -f *.key *.crt *.jks \
	*.csr *.pem *.p12 *.srl extfile

.PHONY: ssl_keys
