#!/usr/bin/env bash
set -e

cd "$(dirname "${0}")" || exit 1
. ./common.sh || exit 1

DEST=../src/lib/inc_generated/ndpi_amazon_aws_match.c.inc
DEST_API_GATEWAY=../src/lib/inc_generated/ndpi_amazon_aws_api_gateway_match.c.inc
DEST_KINESIS=../src/lib/inc_generated/ndpi_amazon_aws_kinesis_match.c.inc
DEST_EC2=../src/lib/inc_generated/ndpi_amazon_aws_ec2_match.c.inc
DEST_S3=../src/lib/inc_generated/ndpi_amazon_aws_s3_match.c.inc
DEST_CLOUDFRONT=../src/lib/inc_generated/ndpi_amazon_aws_cloudfront_match.c.inc
DEST_DYNAMODB=../src/lib/inc_generated/ndpi_amazon_aws_dynamodb_match.c.inc
TMP=/tmp/aws.json
LIST=/tmp/aws.list
LIST6=/tmp/aws.list6
LIST_MERGED=/tmp/aws.list_m
LIST6_MERGED=/tmp/aws.list6_m
ORIGIN=https://ip-ranges.amazonaws.com/ip-ranges.json


echo "(1) Downloading file..."
http_response=$(curl -L -s -o $TMP -w "%{http_code}" ${ORIGIN})
check_http_response "${http_response}"
is_file_empty "${TMP}"

echo "(2) Processing IP addresses..."

# Duplicated service tags in ip-ranges.json (a single prefix can be tagged
# with AMAZON, EC2 and S3 at the same time) made the previous jq selectors
# place the same prefix into several lists. ndpi_aws_ip_dedup.py gives
# every prefix exactly one owner, using a fixed precedence chain:
#   EC2_INSTANCE_CONNECT > EC2 > S3 > CLOUDFRONT > DYNAMODB >
#   API_GATEWAY > KINESIS_VIDEO_STREAMS > AMAZON_AWS (generic)
# Prefixes without any specific service tag stay in the generic list.
# See GitHub issue #3062.

DUP_OUT=/tmp/aws_dedup
mkdir -p ${DUP_OUT}
./ndpi_aws_ip_dedup.py $TMP ${DUP_OUT} || exit 1

# Merge adjacent prefixes inside each service (netaddr.cidr_merge). The
# merge can produce wider networks that cover prefixes kept by a
# lower-precedence list, so a pruning pass removes such covered entries
# afterwards (see ndpi_aws_prune_overlaps.py).
for SVC in API_GATEWAY KINESIS_VIDEO_STREAMS EC2_INSTANCE_CONNECT EC2 S3 CLOUDFRONT DYNAMODB AMAZON_AWS; do
    ./mergeipaddrlist.py ${DUP_OUT}/${SVC}.list   > ${DUP_OUT}/${SVC}.m || true
    ./mergeipaddrlist.py ${DUP_OUT}/${SVC}6.list  > ${DUP_OUT}/${SVC}6.m 2>/dev/null || true
done
# EC2_INSTANCE_CONNECT and EC2 belong to the same nDPI protocol list.
# mergeipaddrlist.py only reads its first argument, so both files are
# concatenated before merging (GitHub issue #3062).
cat ${DUP_OUT}/EC2_INSTANCE_CONNECT.m ${DUP_OUT}/EC2.m            | ./mergeipaddrlist.py /dev/stdin > ${DUP_OUT}/EC2_FINAL.list
cat ${DUP_OUT}/EC2_INSTANCE_CONNECT6.m ${DUP_OUT}/EC26.m 2>/dev/null | ./mergeipaddrlist.py /dev/stdin > ${DUP_OUT}/EC2_FINAL6.list || true

# Prune cross-list overlaps: networks in a higher-precedence list always
# win, so any prefix covered by them is dropped from lower-precedence
# lists before the .inc files are written.
./ndpi_aws_prune_overlaps.py ${DUP_OUT} m || exit 1

#API_GATEWAY
./ipaddr2list.py ${DUP_OUT}/API_GATEWAY.m NDPI_PROTOCOL_AWS_API_GATEWAY ${DUP_OUT}/API_GATEWAY6.m > $DEST_API_GATEWAY
is_file_empty "${DEST_API_GATEWAY}"

#KINESIS
./ipaddr2list.py ${DUP_OUT}/KINESIS_VIDEO_STREAMS.m NDPI_PROTOCOL_AWS_KINESIS ${DUP_OUT}/KINESIS_VIDEO_STREAMS6.m > $DEST_KINESIS
is_file_empty "${DEST_KINESIS}"

#EC2 (EC2 + EC2_INSTANCE_CONNECT merged above)
./ipaddr2list.py ${DUP_OUT}/EC2_FINAL.list NDPI_PROTOCOL_AWS_EC2 ${DUP_OUT}/EC2_FINAL6.list > $DEST_EC2
is_file_empty "${DEST_EC2}"

#S3
./ipaddr2list.py ${DUP_OUT}/S3.m NDPI_PROTOCOL_AWS_S3 ${DUP_OUT}/S36.m > $DEST_S3
is_file_empty "${DEST_S3}"

#CLOUDFRONT
./ipaddr2list.py ${DUP_OUT}/CLOUDFRONT.m NDPI_PROTOCOL_AWS_CLOUDFRONT ${DUP_OUT}/CLOUDFRONT6.m > $DEST_CLOUDFRONT
is_file_empty "${DEST_CLOUDFRONT}"

#DYNAMODB
./ipaddr2list.py ${DUP_OUT}/DYNAMODB.m NDPI_PROTOCOL_AWS_DYNAMODB ${DUP_OUT}/DYNAMODB6.m > $DEST_DYNAMODB
is_file_empty "${DEST_DYNAMODB}"

#Generic
./ipaddr2list.py ${DUP_OUT}/AMAZON_AWS.m NDPI_PROTOCOL_AMAZON_AWS ${DUP_OUT}/AMAZON_AWS6.m > $DEST
is_file_empty "${DEST}"

rm -rf ${TMP} ${LIST} ${LIST6} ${LIST_MERGED} ${LIST6_MERGED} ${DUP_OUT}

echo "(3) Amazon AWS IPs are available in $DEST, $DEST_API_GATEWAY, $DEST_KINESIS, $DEST_EC2, $DEST_S3, $DEST_CLOUDFRONT, $DEST_DYNAMODB"
exit 0
