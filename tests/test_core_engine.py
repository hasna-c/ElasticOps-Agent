import unittest
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from app import core_engine
from app import main as api


class SecurityEngineTests(unittest.TestCase):
    def test_supervisor_builds_search_and_analytics_contracts(self):
        search_state = {"user_query": "Find failed gateway access attempts", "context": {}, "trace": []}
        analytics_state = {"user_query": "Count errors by service", "context": {}, "trace": []}

        core_engine.supervisor_node(search_state)
        core_engine.supervisor_node(analytics_state)

        self.assertEqual(search_state["route"], "threat_specialist")
        self.assertEqual(
            set(search_state["search_payload"]),
            {"target_keywords", "semantic_intent", "filters", "top_k", "rank_window_size"},
        )
        self.assertIn("gateway", search_state["search_payload"]["target_keywords"])
        self.assertEqual(search_state["search_payload"]["semantic_intent"], search_state["user_query"])
        self.assertEqual(analytics_state["route"], "compliance_specialist")
        self.assertEqual(
            set(analytics_state["analytics_payload"]),
            {"query", "aggregation_field", "metric_type", "filters", "bucket_size"},
        )
        self.assertEqual(analytics_state["analytics_payload"]["aggregation_field"], "service")
        self.assertEqual(analytics_state["analytics_payload"]["metric_type"], "error_count")

    def test_cluster_health_is_compliance_analytics_intent(self):
        state = {"user_query": "Summarize cluster health", "context": {}, "trace": []}
        core_engine.supervisor_node(state)
        self.assertEqual(state["route"], "compliance_specialist")
        self.assertEqual(state["analytics_payload"]["metric_type"], "cluster_health")

    def test_serverless_cluster_health_reports_index_availability(self):
        elasticsearch = Mock()
        elasticsearch.info.return_value = {
            "version": {"build_flavor": "serverless", "number": "9.6.0"}
        }
        elasticsearch.indices.exists.return_value = True
        elasticsearch.count.return_value = {"count": 42}
        state = {
            "analytics_payload": {"metric_type": "cluster_health"},
            "raw_cluster_health": {},
            "raw_analytics_results": {},
            "trace": [],
        }

        with patch.object(core_engine, "build_elasticsearch_client", return_value=elasticsearch):
            core_engine.compliance_specialist_node(state)

        elasticsearch.cluster.health.assert_not_called()
        self.assertEqual(state["raw_cluster_health"]["status"], "available")
        self.assertTrue(state["raw_cluster_health"]["index_available"])
        self.assertEqual(state["raw_cluster_health"]["document_count"], 42)

    def test_bootstrap_creates_strict_enterprise_security_index_and_bulk_seeds(self):
        elasticsearch = Mock()
        elasticsearch.indices.exists.return_value = False
        elasticsearch.count.side_effect = [{"count": 0}, {"count": 11}]
        embeddings = Mock()
        embeddings.embed_documents.side_effect = lambda texts: [[0.0] * 384 for _ in texts]

        with (
            patch.object(core_engine, "SEED_SAMPLE_DATA", True),
            patch("app.core_engine.helpers.bulk", return_value=(11, [])) as bulk,
        ):
            result = core_engine.bootstrap_database(elasticsearch, embeddings)

        self.assertEqual(core_engine.INDEX_NAME, "enterprise_security_logs")
        self.assertEqual(result["seeded_documents"], 11)
        self.assertEqual(elasticsearch.indices.create.call_args.kwargs["index"], "enterprise_security_logs")
        body = elasticsearch.indices.create.call_args.kwargs["body"]
        mappings = body["mappings"]
        self.assertEqual(mappings["dynamic"], "strict")
        properties = mappings["properties"]
        self.assertEqual(properties["log_message"], {"type": "text", "analyzer": "standard"})
        self.assertEqual(properties["severity"], {"type": "keyword"})
        self.assertEqual(
            properties["vector_embeddings"],
            {"type": "dense_vector", "dims": 384, "index": True, "similarity": "cosine"},
        )
        actions = bulk.call_args.args[1]
        messages = [action["_source"]["log_message"] for action in actions]
        self.assertTrue(any("45 rapid SSH lookup attempts" in message for message in messages))
        self.assertTrue(any("PUBLIC_READ" in message for message in messages))
        self.assertTrue(any("lateral movement" in message for message in messages))
        self.assertEqual(len(actions[0]["_source"]["vector_embeddings"]), 384)

    def test_bootstrap_omits_shard_settings_for_serverless(self):
        elasticsearch = Mock()
        elasticsearch.info.return_value = {"version": {"build_flavor": "serverless"}}
        elasticsearch.indices.exists.return_value = False
        elasticsearch.count.return_value = {"count": 0}

        with patch.object(core_engine, "SEED_SAMPLE_DATA", False):
            core_engine.bootstrap_database(elasticsearch)

        body = elasticsearch.indices.create.call_args.kwargs["body"]
        self.assertNotIn("settings", body)
        self.assertIn("mappings", body)

    def test_log_ingestion_normalizes_api_fields_and_embeds(self):
        elasticsearch = Mock()
        embeddings = Mock()
        embeddings.embed_documents.return_value = [[0.1] * 384]
        event = {
            "timestamp": "2026-10-08T00:00:00+00:00",
            "level": "error",
            "service": "identity",
            "node": "idp-01",
            "message": "SSH authentication failed for j.doe",
            "source_ip": "10.0.4.12",
            "user_id": "j.doe",
            "target_resource": "payroll_server_01",
        }

        with patch.object(core_engine.helpers, "bulk", return_value=(1, [])) as bulk:
            accepted = core_engine.ingest_log_events([event], elasticsearch, embeddings)

        self.assertEqual(accepted, 1)
        embeddings.embed_documents.assert_called_once_with([event["message"]])
        indexed = bulk.call_args.args[1][0]["_source"]
        self.assertEqual(indexed["severity"], "ERROR")
        self.assertEqual(indexed["host"], "idp-01")
        self.assertEqual(indexed["user_id"], "j.doe")
        self.assertEqual(len(indexed["vector_embeddings"]), 384)

    def test_threat_search_uses_native_rrf_and_returns_security_fields(self):
        elasticsearch = Mock()
        elasticsearch.search.return_value = {
            "hits": {
                "hits": [
                    {
                        "_id": "audit-1",
                        "_source": {
                            "severity": "ERROR",
                            "service": "identity",
                            "host": "payroll_server_01",
                            "user_id": "j.doe",
                            "source_ip": "10.0.4.12",
                            "target_resource": "payroll_server_01",
                            "log_message": "45 rapid SSH authentication attempts for j.doe",
                        },
                    }
                ]
            }
        }
        embeddings = Mock()
        embeddings.embed_query.return_value = [0.1] * 384
        payload = core_engine.SEARCH_PAYLOAD_ADAPTER.validate_python(
            {
                "target_keywords": ["j", "doe", "ssh"],
                "semantic_intent": "Show failed SSH access for j.doe",
                "filters": {"severity": "ERROR"},
                "top_k": 10,
                "rank_window_size": 50,
            }
        )
        state = {
            "user_query": "Show failed SSH access for j.doe",
            "search_payload": payload,
            "raw_search_results": [],
            "trace": [],
        }

        with (
            patch.object(core_engine, "build_elasticsearch_client", return_value=elasticsearch),
            patch.object(core_engine, "build_embedding_client", return_value=embeddings),
        ):
            core_engine.threat_specialist_node(state)

        elasticsearch.search.assert_called_once()
        body = elasticsearch.search.call_args.kwargs["body"]
        rrf = body["retriever"]["rrf"]
        self.assertEqual(rrf["rank_window_size"], 50)
        self.assertEqual(rrf["retrievers"][0]["standard"]["query"]["bool"]["must"][0]["multi_match"]["fields"][0], "log_message^5")
        self.assertEqual(rrf["retrievers"][1]["knn"]["field"], "vector_embeddings")
        self.assertEqual(state["raw_search_results"][0]["_source"]["message"], "45 rapid SSH authentication attempts for j.doe")

    def test_native_rrf_license_denial_falls_back_and_records_reason(self):
        class LicenseDenied(Exception):
            pass

        elasticsearch = Mock()
        elasticsearch.search.side_effect = [
            LicenseDenied("current license is non-compliant for [Reciprocal Rank Fusion (RRF)]"),
            {"hits": {"hits": [{"_id": "lexical-1", "_source": {"log_message": "failed access attempt"}}]}},
            {"hits": {"hits": [{"_id": "vector-1", "_source": {"log_message": "access denied by policy"}}]}},
        ]
        embeddings = Mock()
        embeddings.embed_query.return_value = [0.1] * 384
        state = {
            "user_query": "Find failed access attempts",
            "search_payload": core_engine.SEARCH_PAYLOAD_ADAPTER.validate_python(
                {
                    "target_keywords": ["failed", "access", "attempts"],
                    "semantic_intent": "Find failed access attempts",
                    "filters": {},
                    "top_k": 10,
                    "rank_window_size": 50,
                }
            ),
            "raw_search_results": [],
            "trace": [],
        }

        with (
            patch.object(core_engine, "AuthorizationException", LicenseDenied),
            patch.object(core_engine, "build_elasticsearch_client", return_value=elasticsearch),
            patch.object(core_engine, "build_embedding_client", return_value=embeddings),
        ):
            core_engine.threat_specialist_node(state)

        self.assertEqual(elasticsearch.search.call_count, 3)
        self.assertEqual([hit["_id"] for hit in state["raw_search_results"]], ["lexical-1", "vector-1"])
        self.assertIn("license", state["trace"][0].casefold())

    def test_compliance_aggregates_error_counts_by_service(self):
        elasticsearch = Mock()
        elasticsearch.search.return_value = {"aggregations": {"error_counts_by_service": {"doc_count": 2}}}
        payload = core_engine.ANALYTICS_PAYLOAD_ADAPTER.validate_python(
            {
                "query": "Count errors by service",
                "aggregation_field": "service",
                "metric_type": "error_count",
                "filters": {"service": "identity"},
                "bucket_size": 20,
            }
        )
        state = {"analytics_payload": payload, "raw_analytics_results": {}, "trace": []}

        with patch.object(core_engine, "build_elasticsearch_client", return_value=elasticsearch):
            core_engine.compliance_specialist_node(state)

        query = elasticsearch.search.call_args.kwargs["body"]
        self.assertEqual(query["query"]["bool"]["filter"], [{"term": {"service": "identity"}}])
        self.assertEqual(query["aggs"]["counts_by_field"]["terms"]["field"], "service")
        self.assertEqual(query["aggs"]["error_counts_by_service"]["filter"], {"term": {"severity": "ERROR"}})

    def test_writer_produces_security_brief_without_internal_jargon(self):
        state = {
            "intent": "search",
            "user_query": "show me logs related to j.doe",
            "raw_search_results": [
                {
                    "_source": {
                        "severity": "ERROR",
                        "service": "identity",
                        "host": "payroll_server_01",
                        "source_ip": "10.0.4.12",
                        "user_id": "j.doe",
                        "target_resource": "payroll_server_01",
                        "log_message": "User 'j.doe' from IP 10.0.4.12 initiated 45 rapid SSH lookup attempts on payroll_server_01. AUTH_FAILURE.",
                    }
                }
            ],
            "raw_analytics_results": {},
            "raw_cluster_health": {},
            "final_report": "",
            "trace": [],
        }

        core_engine.writer_node(state)

        self.assertIn("INCIDENT REPORT SUMMARY:", state["final_report"])
        self.assertIn("45 rapid SSH authentication attempts", state["final_report"])
        self.assertIn("j.doe", state["final_report"])
        self.assertIn("payroll_server_01", state["final_report"])
        for internal_term in ("search_specialist", "RRF", "507", "latency"):
            self.assertNotIn(internal_term.casefold(), state["final_report"].casefold())

    def test_writer_recommends_service_checks_for_gateway_timeout(self):
        state = {
            "intent": "search",
            "user_query": "Find recent gateway errors and timeouts",
            "raw_search_results": [
                {
                    "_source": {
                        "severity": "ERROR",
                        "service": "gateway",
                        "host": "gateway-demo",
                        "status_code": 504,
                        "latency_ms": 30000,
                        "log_message": "Gateway request timed out waiting for checkout-api",
                    }
                }
            ],
            "raw_analytics_results": {},
            "raw_cluster_health": {},
            "final_report": "",
            "trace": [],
        }

        core_engine.writer_node(state)

        self.assertIn("gateway-demo", state["final_report"])
        self.assertIn("timed out", state["final_report"].casefold())
        self.assertIn("HTTP 504", state["final_report"])
        self.assertIn("check gateway and upstream service health", state["final_report"].casefold())
        self.assertNotIn("suspend", state["final_report"].casefold())

    def test_writer_does_not_invent_user_evidence(self):
        state = {
            "intent": "search",
            "user_query": "show me logs related to j.doe",
            "raw_search_results": [{"_source": {"severity": "ERROR", "user_id": "admin_alpha", "log_message": "SSH authentication failed"}}],
            "raw_analytics_results": {},
            "raw_cluster_health": {},
            "final_report": "",
            "trace": [],
        }
        core_engine.writer_node(state)
        self.assertIn("No matching security records", state["final_report"])
        self.assertNotIn("payroll", state["final_report"].casefold())

    def test_compliance_writer_reports_real_counts_without_llm(self):
        state = {
            "intent": "analytics",
            "user_query": "Count errors by service",
            "analytics_payload": {"metric_type": "error_count"},
            "raw_analytics_results": {
                "error_counts_by_service": {
                    "doc_count": 2,
                    "services": {"buckets": [{"key": "identity", "doc_count": 1}, {"key": "storage", "doc_count": 1}]},
                }
            },
            "raw_search_results": [],
            "raw_cluster_health": {},
            "final_report": "",
            "trace": [],
        }
        core_engine.writer_node(state)
        self.assertIn("2 ERROR record(s)", state["final_report"])
        self.assertIn("identity: 1", state["final_report"])
        self.assertNotIn("high-priority", state["final_report"].casefold())
        self.assertNotIn("customer-impacting", state["final_report"].casefold())
        self.assertNotIn("error_count", state["final_report"])


class LogIngestionApiTests(unittest.TestCase):
    def test_execute_agent_query_returns_structured_workflow_telemetry(self):
        with (
            patch.object(api, "APP_ENV", "development"),
            patch.object(api, "QUERY_API_KEY", None),
            patch.object(api, "QUERY_USERNAME", None),
            patch.object(api, "execute_agent_query", return_value={
                "intent": "analytics",
                "route": "compliance_specialist",
                "final_report": "SECURITY OPERATIONS SUMMARY",
                "trace": [],
                "supervisor_payload": {},
                "search_payload": None,
                "analytics_payload": {},
                "writer_payload": {},
                "search_results": [],
                "analytics": {},
                "cluster_health": {},
                "agent_execution": [
                    {
                        "agent": "supervisor",
                        "status": "completed",
                        "started_at": "2026-10-08T12:00:00Z",
                        "completed_at": "2026-10-08T12:00:00.100Z",
                        "duration_ms": 100,
                        "result_count": 0,
                    }
                ],
            }),
        ):
            client = TestClient(api.app)
            response = client.post(
                "/api/v1/agent/query",
                json={"user_query": "Count errors by service"},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("request_id", payload)
        self.assertIn("agent_execution", payload)
        self.assertIn(f"request_id={payload['request_id']}", payload["trace"])
        self.assertEqual(payload["agent_execution"][0]["agent"], "supervisor")
        self.assertEqual(payload["agent_execution"][0]["duration_ms"], 100)

    def test_production_elasticsearch_requires_https_and_api_key(self):
        with (
            patch.object(core_engine, "APP_ENV", "production"),
            patch.object(core_engine, "ELASTICSEARCH_URL", "http://elasticsearch:9200"),
            patch.object(core_engine, "ELASTICSEARCH_API_KEY", "test-secret"),
            self.assertRaisesRegex(RuntimeError, "HTTPS"),
        ):
            core_engine.build_elasticsearch_client()

        with (
            patch.object(core_engine, "APP_ENV", "production"),
            patch.object(core_engine, "ELASTICSEARCH_URL", "https://elasticsearch:9200"),
            patch.object(core_engine, "ELASTICSEARCH_API_KEY", None),
            self.assertRaisesRegex(RuntimeError, "API_KEY"),
        ):
            core_engine.build_elasticsearch_client()

    def test_production_ingestion_requires_api_key(self):
        with (
            patch.object(api, "APP_ENV", "production"),
            patch.object(api, "INGEST_API_KEY", "test-secret"),
            patch.object(api, "ingest_log_events") as ingest,
        ):
            client = TestClient(api.app)
            response = client.post(
                "/api/v1/logs/ingest",
                json={"events": [{"level": "ERROR", "service": "identity", "message": "failed login"}]},
            )

        self.assertEqual(response.status_code, 401)
        ingest.assert_not_called()

    def test_development_agent_query_allows_requests_without_auth(self):
        successful_result = {
            "intent": "analytics",
            "route": "compliance_specialist",
            "final_report": "SECURITY OPERATIONS SUMMARY",
            "trace": [],
            "agent_execution": [],
            "supervisor_payload": {},
            "search_payload": None,
            "analytics_payload": {},
            "writer_payload": {},
            "search_results": [],
            "analytics": {},
            "cluster_health": {},
        }
        with (
            patch.object(api, "APP_ENV", "development"),
            patch.object(api, "QUERY_API_KEY", "test-secret"),
            patch.object(api, "execute_agent_query", return_value=successful_result) as execute,
        ):
            client = TestClient(api.app)
            response = client.post(
                "/api/v1/agent/query",
                json={"user_query": "Count errors by service"},
            )

        self.assertEqual(response.status_code, 200)
        execute.assert_called_once()

    def test_production_agent_query_requires_api_key(self):
        successful_result = {
            "intent": "analytics",
            "route": "compliance_specialist",
            "final_report": "SECURITY OPERATIONS SUMMARY",
            "trace": [],
            "agent_execution": [],
            "supervisor_payload": {},
            "search_payload": None,
            "analytics_payload": {},
            "writer_payload": {},
            "search_results": [],
            "analytics": {},
            "cluster_health": {},
        }
        with (
            patch.object(api, "APP_ENV", "production"),
            patch.object(api, "QUERY_API_KEY", "test-secret"),
            patch.object(api, "execute_agent_query", return_value=successful_result) as execute,
        ):
            client = TestClient(api.app)
            missing_credentials = client.post(
                "/api/v1/agent/query",
                json={"user_query": "Count errors by service"},
            )
            invalid_credentials = client.post(
                "/api/v1/agent/query",
                headers={"X-API-Key": "wrong-secret"},
                json={"user_query": "Count errors by service"},
            )
            valid_credentials = client.post(
                "/api/v1/agent/query",
                headers={"X-API-Key": "test-secret"},
                json={"user_query": "Count errors by service"},
            )

        self.assertEqual(missing_credentials.status_code, 401)
        self.assertEqual(invalid_credentials.status_code, 401)
        self.assertEqual(valid_credentials.status_code, 200)
        execute.assert_called_once()

    def test_production_browser_session_can_query_agent(self):
        successful_result = {
            "intent": "analytics",
            "route": "compliance_specialist",
            "final_report": "SECURITY OPERATIONS SUMMARY",
            "trace": [],
            "agent_execution": [],
            "supervisor_payload": {},
            "search_payload": None,
            "analytics_payload": {},
            "writer_payload": {},
            "search_results": [],
            "analytics": {},
            "cluster_health": {},
        }
        with (
            patch.object(api, "APP_ENV", "production"),
            patch.object(api, "bootstrap_database"),
            patch.object(api, "QUERY_API_KEY", None),
            patch.object(api, "QUERY_USERNAME", "security-operator"),
            patch.object(api, "QUERY_PASSWORD", "operator-password"),
            patch.object(api, "QUERY_SESSION_SECRET", "session-secret"),
            patch.object(api, "execute_agent_query", return_value=successful_result) as execute,
        ):
            with TestClient(api.app, base_url="https://testserver") as client:
                login = client.post(
                    "/api/v1/auth/login",
                    json={"username": "security-operator", "password": "operator-password"},
                )
                response = client.post(
                    "/api/v1/agent/query",
                    json={"user_query": "Count errors by service"},
                )

        self.assertEqual(login.status_code, 200)
        self.assertIn("elasticops_session", login.headers.get("set-cookie", ""))
        self.assertEqual(response.status_code, 200)
        execute.assert_called_once()

    def test_agent_query_returns_structured_error_for_execution_failure(self):
        with (
            patch.object(api, "APP_ENV", "development"),
            patch.object(api, "QUERY_API_KEY", None),
            patch.object(api, "QUERY_USERNAME", None),
            patch.object(api, "execute_agent_query", side_effect=RuntimeError("elasticsearch unavailable")),
            patch.object(api, "build_graph", return_value=object()),
        ):
            client = TestClient(api.app)
            response = client.post(
                "/api/v1/agent/query",
                json={"user_query": "Find recent errors"},
            )

        self.assertEqual(response.status_code, 502)
        payload = response.json()
        self.assertEqual(payload["error"], "agent_query_failed")
        self.assertEqual(payload["message"], "The agent query could not be completed.")
        self.assertIn("request_id", payload)

    def test_ingestion_accepts_valid_events_with_configured_key(self):
        event = {"level": "error", "service": "identity", "message": "SSH login failed"}
        with (
            patch.object(api, "APP_ENV", "production"),
            patch.object(api, "INGEST_API_KEY", "test-secret"),
            patch.object(api, "ingest_log_events", return_value=1) as ingest,
        ):
            client = TestClient(api.app)
            response = client.post(
                "/api/v1/logs/ingest",
                headers={"X-API-Key": "test-secret"},
                json={"events": [event]},
            )

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json(), {"accepted": 1, "index": core_engine.INDEX_NAME})
        indexed_event = ingest.call_args.args[0][0]
        self.assertEqual(indexed_event["level"], "ERROR")