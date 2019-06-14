#!/bin/bash

# /**
# * Copyright (C) 2016 Verizon. All Rights Reserved.
# *
# * Licensed under the Apache License, Version 2.0 (the "License");
# * you may not use this file except in compliance with the License.
# * You may obtain a copy of the License at
# *     http://www.apache.org/licenses/LICENSE-2.0
# *
# * Unless required by applicable law or agreed to in writing, software
# * distributed under the License is distributed on an "AS IS" BASIS,
# * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# * See the License for the specific language governing permissions and
# * limitations under the License.
# */


# C example
#   $./c-ectoken/ecencrypt/ec_encrypt decrypt IM_A_KEY $(./c-ectoken/ecencrypt/ec_encrypt IM_A_KEY I_A_SUPER_COOL_STRING)
#   I_A_SUPER_COOL_STRING&ec_secure=052
#   $
# C++ example
#   $ ./c++-ectoken/ectoken -d IM_A_KEY $(./c++-ectoken/ectoken -e IM_A_KEY I_A_SUPER_COOL_STRING)
#   I_A_SUPER_COOL_STRING
#   $
# PHP example
#   $ ./c-ectoken/ecencrypt/ec_encrypt decrypt 12345678 "$(php -d extension=php-ectoken/.libs/ectoken.so -r '$token = ectoken_generate("12345678", "ec_expire=1185943200&ec_clientip=111.11.111.11&ec_country_allow=US&ec_ref_allow=ec1.com"); echo $token;')"
#   ec_expire=1185943200&ec_clientip=111.11.111.11&ec_country_allow=US&ec_ref_allow=ec1.com&ec_secure=111
#   $
# Perl example
#   $./c-ectoken/ecencrypt/ec_encrypt decrypt IM_A_KEY $(./perl-ectoken/ectoken.pl IM_A_KEY I_AM_A_COOL_STRING)
#   I_AM_A_COOL_STRING&ec_secure=047
#   $
# Java example
#   $ java ECToken  encrypt "yourkey" "yourmessage"
#   80be25cb0b9728d50e2e106719791d0ef5a12b5904067720df
#   $ java ECToken  decrypt "yourkey" "80be25cb0b9728d50e2e106719791d0ef5a12b5904067720df"
#   yourmessage

NUM_FAIL=0
UTILITY_NAME_VER="3"

if [ "${VERBOSE}" == "1" ]; then
    set -o xtrace
fi

check_v3_token() {

    set -o errexit

    local key="$1"
    local test_val="$2"

    #local c32_token="$(./c-ectoken/ecencrypt/32/ectoken${UTILITY_NAME_VER} "${key}" "${test_val}")"
    local c64_token="$(./c-ectoken/ecencrypt/64/ectoken${UTILITY_NAME_VER} "${key}" "${test_val}")"
    local py3_token="$(./py3-ectoken/ectoken${UTILITY_NAME_VER}.py --key "${key}" --token "${test_val}")"

    if [[ "$(./c-ectoken/ecencrypt/64/ectoken${UTILITY_NAME_VER} decrypt "${key}" "${c64_token}")" -ne \
          "$(./py3-ectoken/ectoken${UTILITY_NAME_VER}.py --key "${key}" --decrypt --token "${py3_token}")" ]]
    then
        echo "Failure"
        exit 1
    fi

    local py2_token="$(./py2-ectoken/ectoken${UTILITY_NAME_VER}.py --key "${key}" --token "${test_val}")"

    if [[ "$(./c-ectoken/ecencrypt/64/ectoken${UTILITY_NAME_VER} decrypt "${key}" "${c64_token}")" -ne \
          "$(./py2-ectoken/ectoken${UTILITY_NAME_VER}.py --key "${key}" --decrypt --token "${py2_token}")" ]]
    then
        echo "Failure"
        exit 1
    fi

    set +o errexit

    KEY="$1"
    TEST_VAL="$2"
    KEYLEN="$(echo -n $1 | wc -c)"

    set -o errexit

    echo "Starting v3 token checks keylen ${KEYLEN} ------------------------------"

    C32_TOK="$(./c-ectoken/ecencrypt/32/ectoken${UTILITY_NAME_VER} "${KEY}" "${TEST_VAL}")"
    #sleep 1
    C64_TOK="$(./c-ectoken/ecencrypt/64/ectoken${UTILITY_NAME_VER} "${KEY}" "${TEST_VAL}")"
    #sleep 1
    CPP_TOK="$(./c++-ectoken/ectoken${UTILITY_NAME_VER} -e "${KEY}" "${TEST_VAL}")"
    #sleep 1
    PERL_TOK="$(./perl-ectoken/ectoken${UTILITY_NAME_VER}.pl "${KEY}" "${TEST_VAL}")"
    #sleep 1
    PHP_TOK="$(php -d extension=php-ectoken/.libs/ectoken.so -r "\$token = ectoken_encrypt_token('"${KEY}"', '${TEST_VAL}'); echo \$token;")"
    #sleep 1
    JAVA_TOK="$(java -jar java-ectoken/ECToken${UTILITY_NAME_VER}.jar encrypt "${KEY}" "${TEST_VAL}")"
    #sleep 1
    PY3_TOK="$(./py3-ectoken/ectoken${UTILITY_NAME_VER}.py --key "${KEY}" --token "${TEST_VAL}")"
    #sleep 1
    PY2_TOK="$(./py2-ectoken/ectoken${UTILITY_NAME_VER}.py --key "${KEY}" --token "${TEST_VAL}")"

    set +o errexit

    is_valid() {

        NAME="v3 token $2"
        local FAILED=0

        C32_DECRYPT="$(./c-ectoken/ecencrypt/32/ectoken${UTILITY_NAME_VER} decrypt "${KEY}" ${1})"
        echo "${C32_DECRYPT}" | fgrep "${TEST_VAL}" &>/dev/null || {
            echo "FAILURE:  32-bit C decryption check failed for ${NAME}.  Missing original value: ${C32_DECRYPT}"
            let "NUM_FAIL = NUM_FAIL + 1"
            FAILED=1
        }

        C64_DECRYPT="$(./c-ectoken/ecencrypt/64/ectoken${UTILITY_NAME_VER} decrypt "${KEY}" ${1})"
        echo "${C64_DECRYPT}" | fgrep "${TEST_VAL}" &>/dev/null || {
            echo "FAILURE:  64-bit C decryption check failed for ${NAME}.  Missing original value: ${C64_DECRYPT}"
            let "NUM_FAIL = NUM_FAIL + 1"
            FAILED=1
        }

        CPP_DECRYPT="$(./c++-ectoken/ectoken${UTILITY_NAME_VER} -d "${KEY}" ${1})"
        echo "${CPP_DECRYPT}" | fgrep "${TEST_VAL}" &>/dev/null || {
            echo "FAILURE:  C++ decryption check failed for ${NAME}.  Missing original value: ${CPP_DECRYPT}"
            let "NUM_FAIL = NUM_FAIL + 1"
            FAILED=1
        }

        JAVA_DECRYPT="$(java -jar java-ectoken/ECToken${UTILITY_NAME_VER}.jar decrypt "${KEY}" "${1}")"
        echo "${JAVA_DECRYPT}" | fgrep "${TEST_VAL}" &>/dev/null || {
            echo "FAILURE:  Java decryption check failed for ${NAME}.  Missing original value: ${JAVA_DECRYPT}"
            let "NUM_FAIL = NUM_FAIL + 1"
            FAILED=1
        }

        PY3_DECRYPT="$(./py3-ectoken/ectoken${UTILITY_NAME_VER}.py --decrypt --key "${KEY}" --token "${1}")"
        echo "${PY3_DECRYPT}" | fgrep "${TEST_VAL}" &>/dev/null || {
            echo "FAILURE:  Python3 decryption check failed for ${NAME}.  Missing original value: ${PY3_DECRYPT}"
            let "NUM_FAIL = NUM_FAIL + 1"
            FAILED=1
        }

        PY2_DECRYPT="$(./py2-ectoken/ectoken${UTILITY_NAME_VER}.py --decrypt --key "${KEY}" --token "${1}")"
        echo "${PY2_DECRYPT}" | fgrep "${TEST_VAL}" &>/dev/null || {
            echo "FAILURE:  Python2 decryption check failed for ${NAME}.  Missing original value: ${PY2_DECRYPT}"
            let "NUM_FAIL = NUM_FAIL + 1"
            FAILED=1
        }

        if [[ "${FAILED}" = "1" ]]; then
            return 1
        fi

        echo "SUCCESS:  C, C++, Java and Python2/3 correctly decrypt ${NAME}"
    }

    is_valid "${C32_TOK}" "32-bit C, key length: ${KEYLEN}"
    is_valid "${C64_TOK}" "64-bit C, key length: ${KEYLEN}"
    is_valid "${CPP_TOK}" "C++, key length: ${KEYLEN}"
    is_valid "${PHP_TOK}" "PHP, key length: ${KEYLEN}"
    is_valid "${PERL_TOK}" "PERL, key length: ${KEYLEN}"
    is_valid "${JAVA_TOK}" "JAVA, key length: ${KEYLEN}"
    is_valid "${PY3_TOK}" "Python3, key length: ${KEYLEN}"
    is_valid "${PY2_TOK}" "Python2, key length: ${KEYLEN}"

    echo "Done v3 token checks keylen ${KEYLEN} ----------------------------------"

}

check_v3_token "key" "plaintext"
check_v3_token "a" "aaaaaa" # seems to be a bug with decryption for plaintexts shorter than this?
check_v3_token "ec5645a1c604066dbee0d8aba93a23b2bdc471c978ba91232c9380ec67a38590ad856b9b3e432e3b5d033eb52a503a75d458feea7a10278cb392c529ba0929f52a5dde32abec752d5a031fd18778783aaed4123605a93a35c6fe40f1e72a90d9ff00fbf0705ec1e08ee328a2e1521758f4b01d4feaafe0c5125436c8002184ebd51d89a657ec0cda6658f7428009653d3ae4014c4c6974fd7fbf525332f5a49c0fd84aa41909f0c4404abfbf0701af1d5f495810288b57d7b509b6e2fb6e14026c98359250581aace9427e45fee97651bd8b9f3369a53ba5fb1a3370edffdb370e5b656cf87e96ecbb8116112a203a1490eed508118fe2d1949727efa548dabf256" "plaintext"

if [[ "${NUM_FAIL}" != "0" ]]; then
    echo
    echo "----------------------------------"
    echo "Number of failed tests: ${NUM_FAIL}"
    echo "----------------------------------"
    echo
    exit 1
fi
