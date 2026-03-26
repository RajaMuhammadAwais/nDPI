/*
 * unit.c
 *
 * Copyright (C) 2019-20 - ntop.org
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifdef __linux__
#include <sched.h>
#endif /* linux */

#ifdef WIN32
#include <winsock2.h>
#include <process.h>
#include <io.h>
#else
#include <getopt.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/mman.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <search.h>
#include <pcap.h>
#include <signal.h>
#include <pthread.h>
#include <assert.h>
#include <math.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>

#include "ndpi_config.h"
#include "ndpi_api.h"
#include "ndpi_define.h"

#include "json.h" /* JSON-C */

static struct ndpi_detection_module_struct *ndpi_info_mod = NULL;
static int verbose = 0;

/* *********************************************** */

#define FLT_MAX 3.402823466e+38F

int serializerUnitTest() {
  ndpi_serializer serializer, serializer_cloned, deserializer;
  int i, loop_id;
  ndpi_serialization_format fmt = {0};
  u_int32_t buffer_len;
  char *buffer;
  enum json_tokener_error jerr;
  json_object *j;

  memset(&serializer, 0, sizeof(serializer));
  memset(&serializer_cloned, 0, sizeof(serializer_cloned));
  memset(&deserializer, 0, sizeof(deserializer));
  
  for(loop_id=0; loop_id<3; loop_id++) {
    switch(loop_id) {
    case 0:
      if (verbose) printf("--- TLV test ---\n");
      fmt = ndpi_serialization_format_tlv;
      break;

    case 1:
      if (verbose) printf("--- JSON test ---\n");
      fmt = ndpi_serialization_format_json;
      break;

    case 2:
      if (verbose) printf("--- CSV test ---\n");
      fmt = ndpi_serialization_format_csv;
      break;
    }
    assert(ndpi_init_serializer(&serializer, fmt) != -1);

    for(i=0; i<16; i++) {
      char kbuf[32], vbuf[32];
      int j = 0;
      ndpi_snprintf(vbuf, sizeof(vbuf), "Value %d \t with special chars:\n$!@?", i);
      assert(ndpi_serialize_uint32_uint32(&serializer, j++, i*i) != -1);
      assert(ndpi_serialize_uint32_string(&serializer, j++, "Data") != -1);
      ndpi_snprintf(kbuf, sizeof(kbuf), "Key %d", j++);
      assert(ndpi_serialize_string_string(&serializer, kbuf, vbuf) != -1);
      ndpi_snprintf(kbuf, sizeof(kbuf), "Key %d", j++);
      assert(ndpi_serialize_string_uint32(&serializer, kbuf, i*i) != -1);
      ndpi_snprintf(kbuf, sizeof(kbuf), "Key %d", j++);
      assert(ndpi_serialize_string_float(&serializer,  kbuf, (float)(i*i), "%f") != -1);
      if (fmt != ndpi_serialization_format_tlv) {
        ndpi_snprintf(kbuf, sizeof(kbuf), "Key %d", j++);
        assert(ndpi_serialize_string_double(&serializer, kbuf, ((double)(FLT_MAX))*2, "%lf") != -1);
      }
      ndpi_snprintf(kbuf, sizeof(kbuf), "Key %d", j++);
      assert(ndpi_serialize_string_int64(&serializer,  kbuf, INT64_MAX) != -1);
      assert(ndpi_serialize_string_string(&serializer, "utf-8", "küche") != -1);
      if ((i&0x3) == 0x3) ndpi_serialize_end_of_record(&serializer);
    }

    if (fmt == ndpi_serialization_format_json) {
      assert(ndpi_serialize_start_of_list(&serializer, "List") != -1);

      for(i=0; i<4; i++) {
	char kbuf[32], vbuf[32];
	ndpi_snprintf(kbuf, sizeof(kbuf), "Ignored");
	ndpi_snprintf(vbuf, sizeof(vbuf), "Item %d", i);
	assert(ndpi_serialize_uint32_uint32(&serializer, i, i*i) != -1);
	assert(ndpi_serialize_string_string(&serializer, kbuf, vbuf) != -1);
	assert(ndpi_serialize_string_float(&serializer,  kbuf, (float)(i*i), "%f") != -1);
      }
      assert(ndpi_serialize_end_of_list(&serializer) != -1);
      assert(ndpi_serialize_string_string(&serializer, "Last", "Ok") != -1);

      buffer = ndpi_serializer_get_buffer(&serializer, &buffer_len);

      if(verbose)
	printf("%s\n", buffer);

      /* Decoding JSON to validate syntax */
      jerr = json_tokener_success;
      j = json_tokener_parse_verbose(buffer, &jerr);
      if (j == NULL) {
        printf("%s: ERROR (json validation failed: `%s')\n",
               __func__, json_tokener_error_desc(jerr));
        return -1;
      } else {
        /* Validation ok */
        json_object_put(j);
      }

    } else if (fmt == ndpi_serialization_format_csv) {
      if(verbose) {

	buffer_len = 0;
	buffer = ndpi_serializer_get_header(&serializer, &buffer_len);
	printf("%s\n", buffer);

	buffer_len = 0;
	buffer = ndpi_serializer_get_buffer(&serializer, &buffer_len);
	printf("%s\n", buffer);
      }

    } else {
      if(verbose)
	printf("Serialization size: %u\n", ndpi_serializer_get_buffer_len(&serializer));

      assert(ndpi_init_deserializer(&deserializer, &serializer) != -1);

      while(1) {
	ndpi_serialization_type kt, et;

	et = ndpi_deserialize_get_item_type(&deserializer, &kt);

	if(et == ndpi_serialization_unknown) {
	  break;
        } else if(et == ndpi_serialization_end_of_record) {
          if (verbose) printf("EOR\n");
	} else {
	  u_int32_t k32, v32;
          int64_t v64;
	  ndpi_string ks, vs;
	  float vf;
	  double vd;

	  switch(kt) {
          case ndpi_serialization_uint32:
            ndpi_deserialize_key_uint32(&deserializer, &k32);
	    if(verbose) printf("%u=", k32);
	    break;
          case ndpi_serialization_string:
            ndpi_deserialize_key_string(&deserializer, &ks);
            if (verbose) {
              u_int8_t bkp = ks.str[ks.str_len];
	      ks.str[ks.str_len] = '\0';
              printf("%s=", ks.str);
	      ks.str[ks.str_len] = bkp;
            }
	    break;
          default:
            printf("%s: ERROR Unsupported TLV key type %u (value type %u)\n", __func__, kt, et);
	    return -1;
	  }

	  switch(et) {
          case ndpi_serialization_uint32:
	    assert(ndpi_deserialize_value_uint32(&deserializer, &v32) != -1);
	    if(verbose) printf("%u\n", v32);
	    break;

          case ndpi_serialization_int64:
	    assert(ndpi_deserialize_value_int64(&deserializer, &v64) != -1);
	    if(verbose) printf("%" PRId64 "\n", v64);
	    break;

          case ndpi_serialization_string:
	    assert(ndpi_deserialize_value_string(&deserializer, &vs) != -1);
	    if(verbose) {
	      u_int8_t bkp = vs.str[vs.str_len];
	      vs.str[vs.str_len] = '\0';
	      printf("%s\n", vs.str);
	      vs.str[vs.str_len] = bkp;
	    }
	    break;

          case ndpi_serialization_float:
	    assert(ndpi_deserialize_value_float(&deserializer, &vf) != -1);
	    if(verbose) printf("%f\n", vf);
	    break;

          case ndpi_serialization_double:
	    assert(ndpi_deserialize_value_double(&deserializer, &vd) != -1);
	    if(verbose) printf("%lf\n", vd);
	    break;

          default:
	    if (verbose) printf("\n");
            printf("%s: ERROR Unsupported TLV value type %u (key type %u)\n", __func__, et, kt);
	    return -1;
	  }
	}

	ndpi_deserialize_next(&deserializer);
      }

      /* Converting from TLV to JSON */

      assert(ndpi_init_deserializer(&deserializer, &serializer) != -1);
      assert(ndpi_init_serializer(&serializer_cloned, ndpi_serialization_format_json) != -1);
      assert(ndpi_deserialize_clone_all(&deserializer, &serializer_cloned) == 0);

      buffer = ndpi_serializer_get_buffer(&serializer_cloned, &buffer_len);
      if(verbose)
        printf("TLV->JSON: %s\n", buffer);

      ndpi_term_serializer(&serializer_cloned);
    }

    ndpi_term_serializer(&serializer);
  }

  printf("%30s                      OK\n", __func__);
  return 0;
}

/* *********************************************** */

int serializeProtoUnitTest(void)
{
  ndpi_serializer serializer;
  int loop_id;
  ndpi_serialization_format fmt = {0};
  u_int32_t buffer_len;
  char * buffer;

  for(loop_id=0; loop_id<3; loop_id++) {
    switch(loop_id) {
    case 0:
      if (verbose) printf("--- TLV test ---\n");
      fmt = ndpi_serialization_format_tlv;
      break;

    case 1:
      if (verbose) printf("--- JSON test ---\n");
      fmt = ndpi_serialization_format_json;
      break;

    case 2:
      if (verbose) printf("--- CSV test ---\n");
      fmt = ndpi_serialization_format_csv;
      break;
    }
    assert(ndpi_init_serializer(&serializer, fmt) != -1);

    ndpi_protocol ndpi_proto;
    ndpi_risk risks = 0;

    ndpi_proto.proto.master_protocol = NDPI_PROTOCOL_TLS,
      ndpi_proto.proto.app_protocol = NDPI_PROTOCOL_FACEBOOK,
      ndpi_proto.protocol_by_ip = NDPI_PROTOCOL_FACEBOOK,
      ndpi_proto.category = NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK,
      ndpi_proto.breed = NDPI_PROTOCOL_FUN;
       
    NDPI_SET_BIT(risks, NDPI_MALFORMED_PACKET);
    NDPI_SET_BIT(risks, NDPI_TLS_WEAK_CIPHER);
    NDPI_SET_BIT(risks, NDPI_TLS_OBSOLETE_VERSION);
    NDPI_SET_BIT(risks, NDPI_TLS_SELFSIGNED_CERTIFICATE);
    ndpi_serialize_proto(ndpi_info_mod, &serializer, risks, NDPI_CONFIDENCE_DPI, ndpi_proto);
    assert(ndpi_serialize_string_float(&serializer,  "float", FLT_MAX, "%f") != -1);
    if (fmt != ndpi_serialization_format_tlv)
      assert(ndpi_serialize_string_double(&serializer,  "double", ((double)(FLT_MAX))*2, "%lf") != -1);

    if (fmt == ndpi_serialization_format_json)
    {
      buffer_len = 0;
      buffer = ndpi_serializer_get_buffer(&serializer, &buffer_len);
#ifndef WIN32
      char const * const expected_json_str = "{\"flow_risk\": {\"6\": {\"risk\":\"Self-signed Cert\",\"severity\":\"High\",\"risk_score\": {\"total\":300,\"client\":270,\"server\":30}},\"7\": {\"risk\":\"Obsolete TLS (v1.1 or older)\",\"severity\":\"High\",\"risk_score\": {\"total\":310,\"client\":275,\"server\":35}},\"8\": {\"risk\":\"Weak TLS Cipher\",\"severity\":\"High\",\"risk_score\": {\"total\":150,\"client\":135,\"server\":15}},\"17\": {\"risk\":\"Malformed Packet\",\"severity\":\"Low\",\"risk_score\": {\"total\":160,\"client\":80,\"server\":80}}},\"confidence\": {\"6\":\"DPI\"},\"proto\":\"TLS.Facebook\",\"proto_id\":\"91.119\",\"proto_by_ip\":\"Facebook\",\"proto_by_ip_id\":119,\"encrypted\":1,\"breed\":\"Fun\",\"category_id\":6,\"category\":\"SocialNetwork\",\"float\":340282346638528859811704183484516925440.000000,\"double\":680564693277057719623408366969033850880.000000}";

      if (strncmp(buffer, expected_json_str, buffer_len) != 0)
      {
        printf("%s: ERROR: expected JSON str: \"%s\"\n", __func__, expected_json_str);
        printf("%s: ERROR: got JSON str.....: \"%.*s\"\n", __func__, (int)buffer_len, buffer);
        return -1;
      }
#endif

      if(verbose)
        printf("%s\n", buffer);

      /* Decoding JSON to validate syntax */
      enum json_tokener_error jerr = json_tokener_success;
      json_object * const j = json_tokener_parse_verbose(buffer, &jerr);
      if (j == NULL) {
        printf("%s: ERROR (json validation failed: `%s')\n",
               __func__, json_tokener_error_desc(jerr));
        return -1;
      } else {
        /* Validation ok */
        json_object_put(j);
      }
    } else if (fmt == ndpi_serialization_format_csv)
    {
      char const * const expected_csv_hdr_str = "risk,severity,total,client,server,risk,severity,total,client,server,risk,severity,total,client,server,risk,severity,total,client,server,6,proto,proto_id,proto_by_ip,proto_by_ip_id,encrypted,breed,category_id,category,float,double";
      buffer_len = 0;
      buffer = ndpi_serializer_get_header(&serializer, &buffer_len);
      assert(buffer != NULL && buffer_len != 0);
      if (verbose)
        printf("%s\n", buffer);
      if (strncmp(buffer, expected_csv_hdr_str, buffer_len) != 0)
      {
        printf("%s: ERROR: expected CSV str: \"%s\"\n", __func__, expected_csv_hdr_str);
        printf("%s: ERROR: got CSV str.....: \"%.*s\"\n", __func__, (int)buffer_len, buffer);
      }

      char const * const expected_csv_buf_str = "Self-signed Cert,High,300,270,30,Obsolete TLS (v1.1 or older),High,310,275,35,Weak TLS Cipher,High,150,135,15,Malformed Packet,Low,160,80,80,DPI,TLS.Facebook,91.119,Facebook,119,1,Fun,6,SocialNetwork,340282346638528859811704183484516925440.000000,680564693277057719623408366969033850880.000000";
      buffer_len = 0;
      buffer = ndpi_serializer_get_buffer(&serializer, &buffer_len);
      assert(buffer != NULL && buffer_len != 0);
      if (verbose)
          printf("%s\n", buffer);
      if (strncmp(buffer, expected_csv_buf_str, buffer_len) != 0)
      {
        printf("%s: ERROR: expected CSV str: \"%s\"\n", __func__, expected_csv_buf_str);
        printf("%s: ERROR: got CSV str.....: \"%.*s\"\n", __func__, (int)buffer_len, buffer);
      }
    }

    ndpi_term_serializer(&serializer);
  }

  printf("%30s                      OK\n", __func__);

  return 0;
}

/* *********************************************** */

int stringUtilsUnitTest(void) {
  /* ndpi_strnstr */
  assert(ndpi_strnstr("hello world", "world", 11) != NULL);
  assert(ndpi_strnstr("hello world", "xyz", 11) == NULL);
  assert(ndpi_strnstr("hello world", "world", 7) == NULL); /* needle past len */
  assert(ndpi_strnstr("hello", "", 5) != NULL);            /* empty needle */
  assert(ndpi_strnstr("hello", "hello", 5) != NULL);       /* full match */
  assert(ndpi_strnstr("aaa", "aaaa", 3) == NULL);          /* needle longer than haystack */

  /* ndpi_strncasestr */
  assert(ndpi_strncasestr("Hello World", "world", 11) != NULL);
  assert(ndpi_strncasestr("Hello World", "HELLO", 11) != NULL);
  assert(ndpi_strncasestr("Hello World", "xyz", 11) == NULL);

  /* ndpi_strip_leading_trailing_spaces */
  {
    char buf1[] = "  hello  ";
    int len1 = strlen(buf1);
    char *r1 = ndpi_strip_leading_trailing_spaces(buf1, &len1);
    assert(strncmp(r1, "hello", len1) == 0);
    assert(len1 == 5);

    char buf2[] = "no spaces";
    int len2 = strlen(buf2);
    char *r2 = ndpi_strip_leading_trailing_spaces(buf2, &len2);
    assert(strncmp(r2, "no spaces", len2) == 0);
    assert(len2 == 9);

    char buf3[] = "   ";
    int len3 = strlen(buf3);
    ndpi_strip_leading_trailing_spaces(buf3, &len3);
    assert(len3 == 0);
  }

  /* ndpi_check_punycode_string */
  assert(ndpi_check_punycode_string("xn--nxasmq6b.com", 16) == 1);
  assert(ndpi_check_punycode_string("google.com", 10) == 0);
  assert(ndpi_check_punycode_string("xn--a", 5) == 1);   /* punycode prefix detection */
  assert(ndpi_check_punycode_string("abc", 3) == 0);     /* too short to contain "xn--" */

  printf("%30s                      OK\n", __func__);
  return 0;
}

/* *********************************************** */

int hashFunctionsUnitTest(void) {
  /* ndpi_hash_string: same input -> same output */
  assert(ndpi_hash_string("hello") == ndpi_hash_string("hello"));
  assert(ndpi_hash_string("hello") != ndpi_hash_string("world"));
  assert(ndpi_hash_string("") == ndpi_hash_string(""));

  /* ndpi_hash_string_len */
  assert(ndpi_hash_string_len("hello", 5) == ndpi_hash_string_len("hello", 5));
  assert(ndpi_hash_string_len("hello", 3) != ndpi_hash_string_len("hello", 5));

  /* ndpi_quick_hash */
  assert(ndpi_quick_hash((const unsigned char *)"test", 4) ==
         ndpi_quick_hash((const unsigned char *)"test", 4));
  assert(ndpi_quick_hash((const unsigned char *)"test", 4) !=
         ndpi_quick_hash((const unsigned char *)"TEST", 4));

  /* ndpi_murmur_hash */
  assert(ndpi_murmur_hash("hello", 5) == ndpi_murmur_hash("hello", 5));
  assert(ndpi_murmur_hash("hello", 5) != ndpi_murmur_hash("world", 5));

  /* ndpi_nearest_power_of_two */
  assert(ndpi_nearest_power_of_two(1) == 1);
  assert(ndpi_nearest_power_of_two(2) == 2);
  assert(ndpi_nearest_power_of_two(3) == 4);
  assert(ndpi_nearest_power_of_two(5) == 8);
  assert(ndpi_nearest_power_of_two(8) == 8);
  assert(ndpi_nearest_power_of_two(9) == 16);
  assert(ndpi_nearest_power_of_two(1024) == 1024);
  assert(ndpi_nearest_power_of_two(1025) == 2048);

  printf("%30s                      OK\n", __func__);
  return 0;
}

/* *********************************************** */

static int walk_count = 0;
static void hash_walk_cb(char *key, u_int64_t value64, void *data) {
  (void)key;
  (void)value64;
  (void)data;
  walk_count++;
}

int strHashMapUnitTest(void) {
  ndpi_str_hash *h = NULL;
  u_int64_t val = 0;

  /* Init */
  assert(ndpi_hash_init(&h) == 0);
  assert(h != NULL);

  /* Add entries */
  assert(ndpi_hash_add_entry(&h, (char *)"key1", 4, 100, NULL) == 0);
  assert(ndpi_hash_add_entry(&h, (char *)"key2", 4, 200, NULL) == 0);
  assert(ndpi_hash_add_entry(&h, (char *)"key3", 4, 300, NULL) == 0);

  /* Find entries */
  assert(ndpi_hash_find_entry(h, "key1", 4, &val) == 0);
  assert(val == 100);
  assert(ndpi_hash_find_entry(h, "key2", 4, &val) == 0);
  assert(val == 200);
  assert(ndpi_hash_find_entry(h, "key3", 4, &val) == 0);
  assert(val == 300);

  /* Non-existent entry */
  assert(ndpi_hash_find_entry(h, "nokey", 5, &val) != 0);

  /* Walk */
  walk_count = 0;
  ndpi_hash_walk(&h, hash_walk_cb, NULL);
  assert(walk_count == 3);

  /* Overwrite existing key: returns 1 (already present) and updates value */
  assert(ndpi_hash_add_entry(&h, (char *)"key1", 4, 999, NULL) == 1);
  assert(ndpi_hash_find_entry(h, "key1", 4, &val) == 0);
  assert(val == 999);

  /* Free */
  ndpi_hash_free(&h);
  assert(h == NULL);

  printf("%30s                      OK\n", __func__);
  return 0;
}

/* *********************************************** */

int dataAnalysisUnitTest(void) {
  struct ndpi_analyze_struct *s;
  float avg, var, stddev;
  u_int64_t mn, mx, last;

  /* Allocate with a sliding window of 8 */
  s = ndpi_alloc_data_analysis(8);
  assert(s != NULL);

  /* Populate with known values: 2, 4, 4, 4, 5, 5, 7, 9 (classic variance example) */
  ndpi_data_add_value(s, 2);
  ndpi_data_add_value(s, 4);
  ndpi_data_add_value(s, 4);
  ndpi_data_add_value(s, 4);
  ndpi_data_add_value(s, 5);
  ndpi_data_add_value(s, 5);
  ndpi_data_add_value(s, 7);
  ndpi_data_add_value(s, 9);

  /* mean = 5, variance = 4, stddev = 2 */
  avg = ndpi_data_average(s);
  assert(avg >= 4.9f && avg <= 5.1f);

  var = ndpi_data_variance(s);
  assert(var >= 3.8f && var <= 4.2f);

  stddev = ndpi_data_stddev(s);
  assert(stddev >= 1.9f && stddev <= 2.1f);

  mn = ndpi_data_min(s);
  mx = ndpi_data_max(s);
  last = ndpi_data_last(s);
  assert(mn == 2);
  assert(mx == 9);
  assert(last == 9);

  /* Window average (last 8 values same as all values here) */
  float wavg = ndpi_data_window_average(s);
  assert(wavg >= 4.9f && wavg <= 5.1f);

  /* Reset and verify state */
  ndpi_reset_data_analysis(s);
  ndpi_data_add_value(s, 10);
  assert(ndpi_data_min(s) == 10);
  assert(ndpi_data_max(s) == 10);
  assert(ndpi_data_last(s) == 10);

  ndpi_free_data_analysis(s, 1);

  /* ndpi_alloc_data_analysis_from_series */
  u_int32_t series[] = {1, 2, 3, 4, 5};
  s = ndpi_alloc_data_analysis_from_series(series, 5);
  assert(s != NULL);
  avg = ndpi_data_average(s);
  assert(avg >= 2.9f && avg <= 3.1f);
  ndpi_free_data_analysis(s, 1);

  /* ndpi_data_ratio and ndpi_data_ratio2str */
  float ratio;
  ratio = ndpi_data_ratio(0, 0);
  assert(ratio == 0.0f);

  ratio = ndpi_data_ratio(100, 0);  /* pure upload */
  assert(ratio > 0.2f);
  assert(strcmp(ndpi_data_ratio2str(ratio), "Upload") == 0);

  ratio = ndpi_data_ratio(0, 100);  /* pure download */
  assert(ratio < -0.2f);
  assert(strcmp(ndpi_data_ratio2str(ratio), "Download") == 0);

  ratio = ndpi_data_ratio(50, 50);  /* mixed */
  assert(ratio == 0.0f);
  assert(strcmp(ndpi_data_ratio2str(ratio), "Mixed") == 0);

  printf("%30s                      OK\n", __func__);
  return 0;
}

/* *********************************************** */

int bitmapUnitTest(void) {
  ndpi_bitmap *a, *b, *c;
  u_int64_t val;

  /* Basic alloc and empty check */
  a = ndpi_bitmap_alloc();
  assert(a != NULL);
  assert(ndpi_bitmap_is_empty(a) == true);
  assert(ndpi_bitmap_cardinality(a) == 0);

  /* Set and test */
  ndpi_bitmap_set(a, 1);
  ndpi_bitmap_set(a, 100);
  ndpi_bitmap_set(a, 1000);
  assert(ndpi_bitmap_isset(a, 1) == true);
  assert(ndpi_bitmap_isset(a, 100) == true);
  assert(ndpi_bitmap_isset(a, 1000) == true);
  assert(ndpi_bitmap_isset(a, 2) == false);
  assert(ndpi_bitmap_cardinality(a) == 3);
  assert(ndpi_bitmap_is_empty(a) == false);

  /* Unset */
  ndpi_bitmap_unset(a, 100);
  assert(ndpi_bitmap_isset(a, 100) == false);
  assert(ndpi_bitmap_cardinality(a) == 2);

  /* Duplicate set should not increase cardinality */
  ndpi_bitmap_set(a, 1);
  assert(ndpi_bitmap_cardinality(a) == 2);

  /* Copy */
  c = ndpi_bitmap_copy(a);
  assert(c != NULL);
  assert(ndpi_bitmap_cardinality(c) == 2);
  assert(ndpi_bitmap_isset(c, 1) == true);
  assert(ndpi_bitmap_isset(c, 1000) == true);

  /* OR: a={1,1000}, b={2,1000} -> a|b = {1,2,1000} */
  b = ndpi_bitmap_alloc();
  assert(b != NULL);
  ndpi_bitmap_set(b, 2);
  ndpi_bitmap_set(b, 1000);
  ndpi_bitmap_or(a, b);
  assert(ndpi_bitmap_isset(a, 1) == true);
  assert(ndpi_bitmap_isset(a, 2) == true);
  assert(ndpi_bitmap_isset(a, 1000) == true);
  assert(ndpi_bitmap_cardinality(a) == 3);

  /* AND: a={1,2,1000} & c={1,1000} -> {1,1000} */
  ndpi_bitmap_and(a, c);
  assert(ndpi_bitmap_isset(a, 1) == true);
  assert(ndpi_bitmap_isset(a, 2) == false);
  assert(ndpi_bitmap_isset(a, 1000) == true);
  assert(ndpi_bitmap_cardinality(a) == 2);

  /* XOR: a={1,1000} ^ b={2,1000} -> {1,2} */
  ndpi_bitmap_xor(a, b);
  assert(ndpi_bitmap_isset(a, 1) == true);
  assert(ndpi_bitmap_isset(a, 2) == true);
  assert(ndpi_bitmap_isset(a, 1000) == false);
  assert(ndpi_bitmap_cardinality(a) == 2);

  /* Iterator */
  ndpi_bitmap_free(a);
  a = ndpi_bitmap_alloc();
  ndpi_bitmap_set(a, 10);
  ndpi_bitmap_set(a, 20);
  ndpi_bitmap_set(a, 30);
  {
    ndpi_bitmap_iterator *it = ndpi_bitmap_iterator_alloc(a);
    assert(it != NULL);
    u_int64_t count = 0;
    while(ndpi_bitmap_iterator_next(it, &val)) {
      assert(val == 10 || val == 20 || val == 30);
      count++;
    }
    assert(count == 3);
    ndpi_bitmap_iterator_free(it);
  }

  /* Serialize / deserialize */
  {
    char *buf = NULL;
    size_t buf_len = ndpi_bitmap_serialize(a, &buf);
    assert(buf != NULL && buf_len > 0);
    ndpi_bitmap *d = ndpi_bitmap_deserialize(buf, buf_len);
    assert(d != NULL);
    assert(ndpi_bitmap_isset(d, 10) == true);
    assert(ndpi_bitmap_isset(d, 20) == true);
    assert(ndpi_bitmap_isset(d, 30) == true);
    assert(ndpi_bitmap_cardinality(d) == 3);
    ndpi_bitmap_free(d);
    free(buf);
  }

  ndpi_bitmap_free(a);
  ndpi_bitmap_free(b);
  ndpi_bitmap_free(c);

  printf("%30s                      OK\n", __func__);
  return 0;
}

/* *********************************************** */

int bitmap64FuseUnitTest(void) {
  ndpi_bitmap64_fuse *bf = ndpi_bitmap64_fuse_alloc();
  assert(bf != NULL);

  /* Add values including a value exceeding 32-bit range to test 64-bit support */
  assert(ndpi_bitmap64_fuse_set(bf, 1) == true);
  assert(ndpi_bitmap64_fuse_set(bf, 42) == true);
  assert(ndpi_bitmap64_fuse_set(bf, 1000) == true);
  assert(ndpi_bitmap64_fuse_set(bf, UINT32_MAX) == true);
  assert(ndpi_bitmap64_fuse_set(bf, 0x100000000ULL) == true); /* > 32-bit range */

  /* Must compress before query */
  assert(ndpi_bitmap64_fuse_compress(bf) == true);

  /* Query after compression */
  assert(ndpi_bitmap64_fuse_isset(bf, 1) == true);
  assert(ndpi_bitmap64_fuse_isset(bf, 42) == true);
  assert(ndpi_bitmap64_fuse_isset(bf, 1000) == true);
  assert(ndpi_bitmap64_fuse_isset(bf, UINT32_MAX) == true);
  assert(ndpi_bitmap64_fuse_isset(bf, 0x100000000ULL) == true);
  assert(ndpi_bitmap64_fuse_isset(bf, 2) == false);
  assert(ndpi_bitmap64_fuse_isset(bf, 999) == false);

  /* Size should be non-zero after compression */
  assert(ndpi_bitmap64_fuse_size(bf) > 0);

  ndpi_bitmap64_fuse_free(bf);

  /* Empty bitmap: compress on empty should be handled gracefully */
  ndpi_bitmap64_fuse *bf2 = ndpi_bitmap64_fuse_alloc();
  assert(bf2 != NULL);
  assert(ndpi_bitmap64_fuse_compress(bf2) == true);
  assert(ndpi_bitmap64_fuse_isset(bf2, 0) == false);
  ndpi_bitmap64_fuse_free(bf2);

  printf("%30s                      OK\n", __func__);
  return 0;
}

/* *********************************************** */

int riskUtilsUnitTest(void) {
  ndpi_risk_enum risk;
  u_int16_t client_score, server_score;
  ndpi_risk risk_bits;

  /* ndpi_risk2str: verify all risk values return non-NULL strings */
  for(risk = NDPI_NO_RISK; risk < NDPI_MAX_RISK; risk++) {
    const char *s = ndpi_risk2str(risk);
    assert(s != NULL && strlen(s) > 0);
  }

  /* ndpi_risk2score: verify specific risk has non-zero total score */
  risk_bits = 0;
  NDPI_SET_BIT(risk_bits, NDPI_TLS_SELFSIGNED_CERTIFICATE);
  u_int16_t total = ndpi_risk2score(risk_bits, &client_score, &server_score);
  assert(total > 0);
  assert(client_score + server_score == total);

  /* No risk -> zero score */
  risk_bits = 0;
  total = ndpi_risk2score(risk_bits, &client_score, &server_score);
  assert(total == 0);
  assert(client_score == 0);
  assert(server_score == 0);

  /* Multiple risks combine */
  risk_bits = 0;
  NDPI_SET_BIT(risk_bits, NDPI_TLS_SELFSIGNED_CERTIFICATE);
  u_int16_t score_single = ndpi_risk2score(risk_bits, &client_score, &server_score);

  risk_bits = 0;
  NDPI_SET_BIT(risk_bits, NDPI_TLS_SELFSIGNED_CERTIFICATE);
  NDPI_SET_BIT(risk_bits, NDPI_TLS_OBSOLETE_VERSION);
  u_int16_t score_multi = ndpi_risk2score(risk_bits, &client_score, &server_score);
  assert(score_multi > score_single);

  printf("%30s                      OK\n", __func__);
  return 0;
}

/* *********************************************** */

int cryptoUnitTest(void) {
  /* ndpi_md5: known hash for empty string */
  {
    u_char hash[16];
    /* MD5("") = d41d8cd98f00b204e9800998ecf8427e */
    u_char expected[] = {
      0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
      0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e
    };
    ndpi_md5((const u_char *)"", 0, hash);
    assert(memcmp(hash, expected, 16) == 0);

    /* MD5("abc") = 900150983cd24fb0d6963f7d28e17f72 */
    u_char expected_abc[] = {
      0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
      0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72
    };
    ndpi_md5((const u_char *)"abc", 3, hash);
    assert(memcmp(hash, expected_abc, 16) == 0);
  }

  /* ndpi_sha256: known hash for empty string */
  {
    u_int8_t hash[32];
    /* SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 */
    u_int8_t expected[] = {
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
      0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
      0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };
    ndpi_sha256((const u_char *)"", 0, hash);
    assert(memcmp(hash, expected, 32) == 0);
  }

  /* ndpi_crc32: deterministic output for same input */
  {
    u_int32_t crc1 = ndpi_crc32("hello", 5, 0);
    u_int32_t crc2 = ndpi_crc32("hello", 5, 0);
    assert(crc1 == crc2);
    u_int32_t crc3 = ndpi_crc32("world", 5, 0);
    assert(crc1 != crc3);
    /* CRC32("") = 0 when starting from 0 */
    u_int32_t crc_empty = ndpi_crc32("", 0, 0);
    assert(crc_empty == 0);
  }

  /* ndpi_crc16_ccit: deterministic */
  {
    u_int16_t c1 = ndpi_crc16_ccit("hello", 5);
    u_int16_t c2 = ndpi_crc16_ccit("hello", 5);
    assert(c1 == c2);
    u_int16_t c3 = ndpi_crc16_ccit("world", 5);
    assert(c1 != c3);
  }

  /* ndpi_hex2bin and ndpi_bin2hex round trip */
  {
    u_char binary[4];
    u_char hex_out[9]; /* 4 bytes * 2 hex chars + '\0' */

    /* Decode "deadbeef" */
    u_int decoded = ndpi_hex2bin(binary, sizeof(binary), (u_char *)"deadbeef", 8);
    assert(decoded == 4);
    assert(binary[0] == 0xde);
    assert(binary[1] == 0xad);
    assert(binary[2] == 0xbe);
    assert(binary[3] == 0xef);

    /* Encode back */
    u_int encoded = ndpi_bin2hex(hex_out, sizeof(hex_out), binary, 4);
    assert(encoded == 8);
    hex_out[8] = '\0';
    assert(strncasecmp((char *)hex_out, "deadbeef", 8) == 0);
  }

  printf("%30s                      OK\n", __func__);
  return 0;
}

/* *********************************************** */

int protocolModuleUnitTest(void) {
  /* API version should match */
  assert(ndpi_get_api_version() == NDPI_API_VERSION);

  /* ndpi_revision: non-NULL, non-empty string */
  char *rev = ndpi_revision();
  assert(rev != NULL && strlen(rev) > 0);

  /* ndpi_get_num_protocols: should be > 0 */
  u_int num = ndpi_get_num_protocols(ndpi_info_mod);
  assert(num > 0);

  /* ndpi_get_proto_name for UNKNOWN */
  char *name = ndpi_get_proto_name(ndpi_info_mod, NDPI_PROTOCOL_UNKNOWN);
  assert(name != NULL);

  /* ndpi_get_proto_name for TLS (well-known protocol) */
  name = ndpi_get_proto_name(ndpi_info_mod, NDPI_PROTOCOL_TLS);
  assert(name != NULL && strlen(name) > 0);

  /* ndpi_get_proto_breed */
  ndpi_protocol_breed_t breed = ndpi_get_proto_breed(ndpi_info_mod, NDPI_PROTOCOL_TLS);
  assert(breed >= NDPI_PROTOCOL_UNRATED && breed <= NDPI_PROTOCOL_TRACKER_ADS);

  /* ndpi_get_proto_breed_name: non-NULL for all valid breeds */
  for(int i = NDPI_PROTOCOL_UNRATED; i <= NDPI_PROTOCOL_TRACKER_ADS; i++) {
    char *bname = ndpi_get_proto_breed_name((ndpi_protocol_breed_t)i);
    assert(bname != NULL && strlen(bname) > 0);
  }

  /* ndpi_get_breed_by_name round-trip */
  char *bname = ndpi_get_proto_breed_name(NDPI_PROTOCOL_SAFE);
  assert(bname != NULL);
  ndpi_protocol_breed_t b2 = ndpi_get_breed_by_name(bname);
  assert(b2 == NDPI_PROTOCOL_SAFE);

  /* ndpi_get_proto_category */
  {
    ndpi_protocol proto;
    memset(&proto, 0, sizeof(proto));
    proto.proto.master_protocol = NDPI_PROTOCOL_UNKNOWN;
    proto.proto.app_protocol = NDPI_PROTOCOL_TLS;
    ndpi_protocol_category_t cat = ndpi_get_proto_category(ndpi_info_mod, proto);
    assert((int)cat >= 0);

    /* ndpi_category_get_name: non-NULL */
    const char *cat_name = ndpi_category_get_name(ndpi_info_mod, cat);
    assert(cat_name != NULL);
  }

  /* ndpi_is_subprotocol_informative */
  u_int8_t inf = ndpi_is_subprotocol_informative(ndpi_info_mod, NDPI_PROTOCOL_TLS);
  assert(inf == 0 || inf == 1);

  /* ndpi_detection_get_sizeof_ndpi_flow_struct: reasonable size */
  u_int32_t flow_sz = ndpi_detection_get_sizeof_ndpi_flow_struct();
  assert(flow_sz > 0 && flow_sz < 1024 * 1024); /* sanity check */

  printf("%30s                      OK\n", __func__);
  return 0;
}

/* *********************************************** */

int main(int argc, char **argv) {
#ifndef WIN32
  int c;
#endif
  (void)argc;
  (void)argv;
  
  if (ndpi_get_api_version() != NDPI_API_VERSION) {
    printf("nDPI Library version mismatch: please make sure this code and the nDPI library are in sync\n");
    return -1;
  }

  ndpi_info_mod = ndpi_init_detection_module(NULL);

  if (ndpi_info_mod == NULL)
    return -1;

  if(ndpi_finalize_initialization(ndpi_info_mod) != 0)
    return -1;

/*
 * If we want argument parsing on Windows,
 * we need to re-implement it as Windows has no such function.
 */
#ifndef WIN32
  while((c = getopt(argc, argv, "vh")) != -1) {
    switch(c) {
    case 'v':
      verbose = 1;
      break;
      
    default:
      printf("Usage: unit [-v] [-h]\n");
      return(0);
    }
  }
#else
  verbose = 0;
#endif
    
  /* Tests */
  if (serializerUnitTest() != 0) return -1;
  if (serializeProtoUnitTest() != 0) return -1;
  if (stringUtilsUnitTest() != 0) return -1;
  if (hashFunctionsUnitTest() != 0) return -1;
  if (strHashMapUnitTest() != 0) return -1;
  if (dataAnalysisUnitTest() != 0) return -1;
  if (bitmapUnitTest() != 0) return -1;
  if (bitmap64FuseUnitTest() != 0) return -1;
  if (riskUtilsUnitTest() != 0) return -1;
  if (cryptoUnitTest() != 0) return -1;
  if (protocolModuleUnitTest() != 0) return -1;

  ndpi_exit_detection_module(ndpi_info_mod);

  return 0;
}

