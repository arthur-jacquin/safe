TEST_KEY = test-key
TEST_PASSWORD = test-password
TEST_USERNAME = test-username
TEST_SEPARATOR = test-sep
TEST_LENGTH = 17

TESTS = \
	test_cryptographic \
	test_io_standard \
	test_io_file \
	test_usage_optional_parameter_error \
	test_usage_positional_argument_error \
	test_usage_file_error \
	test_usage_parameter_overloading \
	test_usage_key_file \
	test_usage_notes \
	test_usage_ad_hoc_notes \
	test_usage_username_generation_custom_length \
	test_query_format_error \
	test_query_username \
	test_query_username_absence_error \
	test_query_custom_format \
	test_query_separator

.PHONY: ${TESTS}

test_cryptographic: crypto.tests
	@echo "[TESTS] Cryptographic tests..."
	./$<

test_io_standard: safe
	@echo "[TESTS] Using standard input/output..."
	./safe -k ${TEST_KEY} -p ${TEST_PASSWORD} > entry.test
	cat entry.test | ./safe -k ${TEST_KEY} - > output.test
	echo ${TEST_PASSWORD} | cmp - output.test

test_io_file: safe
	@echo "[TESTS] Using file input/output..."
	./safe -k ${TEST_KEY} -p ${TEST_PASSWORD} -o entry.test
	./safe -k ${TEST_KEY} -o output.test entry.test
	echo ${TEST_PASSWORD} | cmp - output.test

test_usage_optional_parameter_error: safe
	@echo "[TESTS] Handling invalid parameter or parameter value..."
	!(./safe -k ${TEST_KEY} --encryption chacha20)
	!(./safe -k ${TEST_KEY} --password-character-set unknown-identifier)
	!(./safe -k ${TEST_KEY} --password-length not-a-number)
	!(./safe -k ${TEST_KEY} --password-length 100)

test_usage_positional_argument_error: safe
	@echo "[TESTS] Handling invalid positional arguments..."
	./safe -k ${TEST_KEY} -p ${TEST_PASSWORD} > entry.test
	!(./safe -k ${TEST_KEY} entry.test entry.test)
	!(./safe -k ${TEST_KEY} entry.test -o output.test)

test_usage_file_error: safe
	@echo "[TESTS] Handling missing file..."
	rm -f entry.test
	!(./safe -k ${TEST_KEY} entry.test)

test_usage_parameter_overloading: safe
	@echo "[TESTS] Handling parameter overloading..."
	./safe -k wrong-key -k ${TEST_KEY} -p ${TEST_PASSWORD} > entry.test
	./safe -k ${TEST_KEY} entry.test > output.test
	echo ${TEST_PASSWORD} | cmp - output.test

test_usage_key_file: safe
	@echo "[TESTS] Handling a file as a key..."
	./safe -K README -p ${TEST_PASSWORD} > entry.test
	./safe -K README entry.test > output.test
	echo ${TEST_PASSWORD} | cmp - output.test

test_usage_notes: safe
	@echo "[TESTS] Handling notes..."
	./safe -k ${TEST_KEY} -p ${TEST_PASSWORD} -n "Additional line" > entry.test
	sed -n 3,\$$p entry.test > output.test
	echo "Additional line" | cmp - output.test
	./safe -k ${TEST_KEY} entry.test > output.test
	echo ${TEST_PASSWORD} | cmp - output.test

test_usage_ad_hoc_notes: safe
	@echo "[TESTS] Handling external metadata..."
	./safe -k ${TEST_KEY} -p ${TEST_PASSWORD} > entry.test
	echo "Additional line" >> entry.test
	./safe -k ${TEST_KEY} entry.test > output.test
	echo ${TEST_PASSWORD} | cmp - output.test

test_usage_username_generation_custom_length: safe
	@echo "[TESTS] Handling randomly generated username..."
	./safe -k ${TEST_KEY} -U -L ${TEST_LENGTH} > entry.test
	U=`./safe -k ${TEST_KEY} -1 entry.test` && test $${#U} -eq ${TEST_LENGTH}

test_query_format_error: safe
	@echo "[TESTS] Querying on an invalid or corrupted file..."
	!(./safe -k ${TEST_KEY} README)

test_query_username: safe
	@echo "[TESTS] Querying username..."
	./safe -k ${TEST_KEY} -p ${TEST_PASSWORD} -u ${TEST_USERNAME} > entry.test
	./safe -k ${TEST_KEY} -1 entry.test > output.test
	echo ${TEST_USERNAME} | cmp - output.test

test_query_username_absence_error: safe
	@echo "[TESTS] Querying non-specified username..."
	./safe -k ${TEST_KEY} -p ${TEST_PASSWORD} > entry.test
	!(./safe -k ${TEST_KEY} -1 entry.test)

test_query_custom_format: safe
	@echo "[TESTS] Querying custom format..."
	./safe -k ${TEST_KEY} -p ${TEST_PASSWORD} -u ${TEST_USERNAME} > entry.test
	./safe -k ${TEST_KEY} -f ":%u__%p:" entry.test > output.test
	echo :${TEST_USERNAME}__${TEST_PASSWORD}: | cmp - output.test

test_query_separator: safe
	@echo "[TESTS] Querying using separator..."
	./safe -k ${TEST_KEY} -p ${TEST_PASSWORD} -u ${TEST_USERNAME} > entry.test
	./safe -k ${TEST_KEY} -s ${TEST_SEPARATOR} entry.test > output.test
	echo ${TEST_USERNAME}${TEST_SEPARATOR}${TEST_PASSWORD} | cmp - output.test
