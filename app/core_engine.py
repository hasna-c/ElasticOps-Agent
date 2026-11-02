import logging
import os
import re
import time
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Dict, List, Literal

from elasticsearch import Elasticsearch, helpers
from elasticsearch.exceptions import AuthorizationException
from langchain_community.embeddings import HuggingFaceEmbeddings
from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter
from typing_extensions import TypedDict

LOGGER = logging.getLogger("elasticops")

INDEX_NAME = "enterprise_security_logs"
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
ELASTICSEARCH_API_KEY = os.getenv("ELASTICSEARCH_API_KEY")
ELASTICSEARCH_CA_CERTS = os.getenv("ELASTICSEARCH_CA_CERTS")
APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
_SEED_DEFAULT = APP_ENV not in {"prod", "production"}
SEED_SAMPLE_DATA = os.getenv("ELASTICOPS_SEED_SAMPLE_DATA", str(_SEED_DEFAULT)).strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
ELASTICSEARCH_NUMBER_OF_SHARDS = int(os.getenv("ELASTICSEARCH_NUMBER_OF_SHARDS", "1"))
_REPLICA_DEFAULT = "1" if APP_ENV in {"prod", "production"} else "0"
ELASTICSEARCH_NUMBER_OF_REPLICAS = int(os.getenv("ELASTICSEARCH_NUMBER_OF_REPLICAS", _REPLICA_DEFAULT))


class SearchPayload(TypedDict):
    target_keywords: List[str]
    semantic_intent: str
    filters: Dict[str, Any]
    top_k: int
    rank_window_size: int


class AnalyticsPayload(TypedDict):
    query: str
    aggregation_field: str
    metric_type: Literal["error_count", "event_count", "severity_distribution", "cluster_health"]
    filters: Dict[str, Any]
    bucket_size: int


SEARCH_PAYLOAD_ADAPTER = TypeAdapter(SearchPayload)
ANALYTICS_PAYLOAD_ADAPTER = TypeAdapter(AnalyticsPayload)


class SupervisorPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intent: Literal["search", "analytics"]
    user_query: str = Field(..., min_length=1, max_length=5000)
    target_node: Literal["threat_specialist", "compliance_specialist"]
    confidence: float = Field(..., ge=0.0, le=1.0)
    normalized_keywords: List[str]


class WriterPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    report_type: Literal["security_incident", "security_analytics", "platform_health"]
    focus: str = Field(..., min_length=1, max_length=5000)
    evidence_count: int = Field(..., ge=0)


class AgentMeshState(TypedDict):
    user_query: str
    context: Dict[str, str]
    intent: str
    route: str
    supervisor_payload: Dict[str, Any]
    search_payload: SearchPayload | None
    analytics_payload: AnalyticsPayload | None
    writer_payload: Dict[str, Any]
    raw_search_results: List[Dict[str, Any]]
    raw_analytics_results: Dict[str, Any]
    raw_cluster_health: Dict[str, Any]
    final_report: str
    trace: List[str]
    agent_execution: List[Dict[str, Any]]


GraphState = AgentMeshState


def build_elasticsearch_client() -> Elasticsearch:
    if APP_ENV in {"prod", "production"}:
        if not ELASTICSEARCH_URL.startswith("https://"):
            raise RuntimeError("Production Elasticsearch connections must use HTTPS")
        if not ELASTICSEARCH_API_KEY:
            raise RuntimeError("Production Elasticsearch connections require ELASTICSEARCH_API_KEY")

    options: Dict[str, Any] = {"request_timeout": 30, "retry_on_timeout": True}
    if ELASTICSEARCH_API_KEY:
        options["api_key"] = ELASTICSEARCH_API_KEY
    if ELASTICSEARCH_CA_CERTS:
        options["ca_certs"] = ELASTICSEARCH_CA_CERTS
    return Elasticsearch(ELASTICSEARCH_URL, **options)


@lru_cache(maxsize=1)
def build_embedding_client() -> HuggingFaceEmbeddings:
    return HuggingFaceEmbeddings(
        model_name="sentence-transformers/all-MiniLM-L6-v2",
        model_kwargs={"device": "cpu"},
        encode_kwargs={"normalize_embeddings": True},
    )


def _security_sample_events() -> List[Dict[str, Any]]:
    return [
        {
            "timestamp": "2026-10-08T08:00:00Z",
            "severity": "ERROR",
            "service": "identity",
            "host": "payroll_server_01",
            "source_ip": "10.0.4.12",
            "user_id": "j.doe",
            "target_resource": "payroll_server_01",
            "status_code": 401,
            "log_message": "Security Event Audit: User 'j.doe' from IP 10.0.4.12 initiated 45 rapid SSH lookup attempts on payroll_server_01. System flag: AUTH_FAILURE.",
        },
        {
            "timestamp": "2026-10-08T08:04:00Z",
            "severity": "CRITICAL",
            "service": "storage-audit",
            "host": "cloud-audit-01",
            "user_id": "admin_alpha",
            "target_resource": "secure_storage_bucket_shared",
            "status_code": 200,
            "log_message": "Access Log: User 'admin_alpha' modified access policies on secure_storage_bucket_shared, changing permissions from PRIVATE to PUBLIC_READ.",
        },
        {
            "timestamp": "2026-10-08T08:08:00Z",
            "severity": "CRITICAL",
            "service": "database-audit",
            "host": "db-audit-02",
            "user_id": "contractor_temp",
            "target_resource": "executive_financial_db",
            "status_code": 403,
            "log_message": "System Alert: Potential lateral movement detected. Unauthorized user profile 'contractor_temp' attempted file extraction on executive_financial_db.",
        },
        {
            "timestamp": "2026-10-08T08:10:00Z",
            "severity": "ERROR",
            "service": "identity",
            "host": "idp_primary_01",
            "source_ip": "10.0.4.18",
            "user_id": "svc_backup",
            "target_resource": "identity_provider",
            "status_code": 401,
            "log_message": "Authentication audit: service account svc_backup presented an expired credential during a scheduled backup sign-in.",
        },
        {
            "timestamp": "2026-10-08T08:14:00Z",
            "severity": "WARN",
            "service": "network-security",
            "host": "edge_firewall_02",
            "source_ip": "198.51.100.24",
            "user_id": "unknown",
            "target_resource": "admin_console",
            "status_code": 403,
            "log_message": "Network audit: inbound connection from 198.51.100.24 to the administrative console was blocked by the perimeter access policy.",
        },
        {
            "timestamp": "2026-10-08T08:19:00Z",
            "severity": "INFO",
            "service": "configuration-audit",
            "host": "config_controller_01",
            "user_id": "change_operator_07",
            "target_resource": "firewall_policy_revision_1842",
            "status_code": 200,
            "log_message": "Configuration audit: approved firewall policy revision 1842 was applied and its signed change record was verified.",
        },
        {
            "timestamp": "2026-10-08T08:24:00Z",
            "severity": "ERROR",
            "service": "dns-security",
            "host": "resolver_03",
            "source_ip": "10.0.8.15",
            "target_resource": "identity_provider_dns",
            "status_code": 503,
            "log_message": "Network error: recursive DNS lookups for the identity provider failed after repeated upstream resolver timeouts.",
        },
        {
            "timestamp": "2026-10-08T08:31:00Z",
            "severity": "WARN",
            "service": "certificate-audit",
            "host": "certificate_manager_02",
            "user_id": "system_renewal",
            "target_resource": "internal_api_certificate",
            "status_code": 200,
            "log_message": "Certificate audit: the internal API certificate entered its renewal window and is awaiting validation.",
        },
        {
            "timestamp": "2026-10-08T08:36:00Z",
            "severity": "ERROR",
            "service": "storage-audit",
            "host": "audit_volume_07",
            "user_id": "audit_writer",
            "target_resource": "security_audit_volume",
            "status_code": 507,
            "log_message": "Audit storage write failed when the security event volume reached its configured capacity threshold.",
        },
        {
            "timestamp": "2026-10-08T08:42:00Z",
            "severity": "INFO",
            "service": "deployment-audit",
            "host": "orchestrator_01",
            "user_id": "release_service",
            "target_resource": "infrastructure_release_2026_10_08",
            "status_code": 200,
            "log_message": "Deployment audit: signed infrastructure release completed on six hosts and passed verification checks.",
        },
        {
            "timestamp": "2026-10-08T08:49:00Z",
            "severity": "WARN",
            "service": "elasticsearch-audit",
            "host": "data_node_01",
            "user_id": "indexing_service",
            "target_resource": "enterprise_security_logs",
            "status_code": 429,
            "log_message": "Audit indexing backpressure increased while a primary shard recovered after a data node restart.",
        },
    ]


def bootstrap_database(
    elasticsearch_client: Elasticsearch | None = None,
    embedding_client: HuggingFaceEmbeddings | None = None,
) -> Dict[str, Any]:
    client = elasticsearch_client or build_elasticsearch_client()
    server_info = client.info()
    is_serverless = server_info.get("version", {}).get("build_flavor") == "serverless"
    mappings = {
        "timestamp": {"type": "date"},
        "log_message": {"type": "text", "analyzer": "standard"},
        "severity": {"type": "keyword"},
        "vector_embeddings": {
            "type": "dense_vector",
            "dims": 384,
            "index": True,
            "similarity": "cosine",
        },
        "service": {"type": "keyword"},
        "host": {"type": "keyword"},
        "source_ip": {"type": "ip"},
        "user_id": {"type": "keyword"},
        "target_resource": {"type": "keyword"},
        "status_code": {"type": "integer"},
        "trace_id": {"type": "keyword"},
        "environment": {"type": "keyword"},
    }

    if client.indices.exists(index=INDEX_NAME):
        client.indices.put_mapping(
            index=INDEX_NAME,
            body={"dynamic": "strict", "properties": mappings},
        )
    else:
        index_body = {"mappings": {"dynamic": "strict", "properties": mappings}}
        if not is_serverless:
            index_body["settings"] = {
                "number_of_shards": ELASTICSEARCH_NUMBER_OF_SHARDS,
                "number_of_replicas": ELASTICSEARCH_NUMBER_OF_REPLICAS,
            }
        client.indices.create(
            index=INDEX_NAME,
            body=index_body,
        )

    document_count = int(client.count(index=INDEX_NAME).get("count", 0))
    seeded_documents = 0
    if document_count == 0 and SEED_SAMPLE_DATA:
        model = embedding_client or build_embedding_client()
        events = _security_sample_events()
        vectors = model.embed_documents([event["log_message"] for event in events])
        actions = [
            {
                "_op_type": "index",
                "_index": INDEX_NAME,
                "_id": f"security-sample-{index + 1:04d}",
                "_source": {**event, "vector_embeddings": vector},
            }
            for index, (event, vector) in enumerate(zip(events, vectors))
        ]
        helpers.bulk(client, actions, refresh=True, raise_on_error=True)
        seeded_documents = len(actions)

    document_count = int(client.count(index=INDEX_NAME).get("count", 0))
    LOGGER.info("Security index %s is ready with %s records", INDEX_NAME, document_count)
    return {
        "index": INDEX_NAME,
        "documents": document_count,
        "seeded_documents": seeded_documents,
        "status": "ready",
    }


def ingest_log_events(
    events: List[Dict[str, Any]],
    elasticsearch_client: Elasticsearch | None = None,
    embedding_client: HuggingFaceEmbeddings | None = None,
) -> int:
    client = elasticsearch_client or build_elasticsearch_client()
    model = embedding_client or build_embedding_client()
    normalized_events = []
    for event in events:
        log_message = str(event.get("log_message") or event.get("message") or "").strip()
        if not log_message:
            raise ValueError("Each security event requires log_message or message text")
        severity = str(event.get("severity") or event.get("level") or "INFO").strip().upper()
        normalized_events.append(
            {
                "timestamp": event.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                "log_message": log_message,
                "severity": severity,
                "service": str(event.get("service") or "unknown"),
                "host": str(event.get("host") or event.get("node") or "unknown"),
                "source_ip": event.get("source_ip") or event.get("ip_address"),
                "user_id": event.get("user_id") or event.get("username"),
                "target_resource": event.get("target_resource") or event.get("resource"),
                "status_code": event.get("status_code"),
                "trace_id": event.get("trace_id"),
                "environment": event.get("environment"),
            }
        )

    vectors = model.embed_documents([event["log_message"] for event in normalized_events])
    actions = [
        {
            "_op_type": "index",
            "_index": INDEX_NAME,
            "_source": {**event, "vector_embeddings": vector},
        }
        for event, vector in zip(normalized_events, vectors)
    ]
    accepted, _ = helpers.bulk(client, actions, refresh="wait_for", raise_on_error=True)
    return int(accepted)


def _tokenize(text: str) -> List[str]:
    return re.findall(r"[a-z0-9_]+", text.casefold())


def _context_filters(context: Dict[str, str]) -> Dict[str, Any]:
    filters = {}
    for field in ("service", "severity", "host", "source_ip", "user_id", "target_resource"):
        value = context.get(field)
        if value:
            filters[field] = value
    if context.get("level") and "severity" not in filters:
        filters["severity"] = context["level"].upper()
    if context.get("node") and "host" not in filters:
        filters["host"] = context["node"]
    return filters


def _record_agent_started(state: AgentMeshState, agent: str) -> float:
    state.setdefault("agent_execution", [])
    started_at = datetime.now(timezone.utc).isoformat()
    state["agent_execution"].append(
        {
            "agent": agent,
            "status": "completed",
            "started_at": started_at,
            "completed_at": started_at,
            "duration_ms": 0,
            "result_count": 0,
        }
    )
    return time.perf_counter()


def _record_agent_completed(
    state: AgentMeshState,
    agent: str,
    started_at: float,
    result_count: int,
) -> None:
    execution = state["agent_execution"][-1]
    if execution["agent"] != agent:
        return
    completed_at = datetime.now(timezone.utc).isoformat()
    execution["status"] = "completed"
    execution["completed_at"] = completed_at
    execution["duration_ms"] = max(0, round((time.perf_counter() - started_at) * 1000))
    execution["result_count"] = result_count


def supervisor_node(state: AgentMeshState) -> AgentMeshState:
    started_at = _record_agent_started(state, "supervisor")
    query = state["user_query"].strip()
    tokens = _tokenize(query)
    token_set = set(tokens)
    context = state.get("context", {})
    filters = _context_filters(context)
    cluster_health_query = "cluster" in token_set and bool(token_set & {"health", "status", "healthy"})
    analytical_query = cluster_health_query or bool(
        token_set
        & {
            "aggregate",
            "aggregation",
            "analytics",
            "by",
            "count",
            "counts",
            "distribution",
            "frequency",
            "group",
            "statistics",
            "stats",
            "summary",
            "summarize",
            "summarise",
            "trend",
        }
    )

    if analytical_query:
        intent = "analytics"
        target_node = "compliance_specialist"
        if cluster_health_query:
            aggregation_field = "service"
            metric_type: Literal["error_count", "event_count", "severity_distribution", "cluster_health"] = "cluster_health"
        else:
            aggregation_field = "host" if "host" in token_set else "severity" if "severity" in token_set else "service"
            metric_type = "error_count" if any(token.startswith("error") or token.startswith("fail") for token in tokens) else "event_count"
        analytics_payload = ANALYTICS_PAYLOAD_ADAPTER.validate_python(
            {
                "query": query,
                "aggregation_field": aggregation_field,
                "metric_type": metric_type,
                "filters": filters,
                "bucket_size": 20,
            }
        )
        state["analytics_payload"] = analytics_payload
        state["search_payload"] = None
    else:
        intent = "search"
        target_node = "threat_specialist"
        stop_words = {"a", "an", "and", "are", "for", "from", "in", "is", "of", "on", "the", "to", "with"}
        target_keywords = [token for token in tokens if token not in stop_words]
        search_payload = SEARCH_PAYLOAD_ADAPTER.validate_python(
            {
                "target_keywords": target_keywords or tokens,
                "semantic_intent": query,
                "filters": filters,
                "top_k": 10,
                "rank_window_size": 50,
            }
        )
        state["search_payload"] = search_payload
        state["analytics_payload"] = None

    supervisor_payload = SupervisorPayload(
        intent=intent,
        user_query=query,
        target_node=target_node,
        confidence=0.96 if analytical_query else 0.91,
        normalized_keywords=tokens,
    )
    state["intent"] = intent
    state["route"] = target_node
    state["supervisor_payload"] = supervisor_payload.model_dump(mode="json")
    state["trace"].append(f"Supervisor created the validated A2A contract for {target_node}.")
    _record_agent_completed(
        state,
        "supervisor",
        started_at,
        len(state["supervisor_payload"].get("normalized_keywords", [])),
    )
    return state


def _merge_ranked_lists(
    lexical_hits: List[Dict[str, Any]],
    vector_hits: List[Dict[str, Any]],
    rank_window_size: int,
    rank_constant: int = 60,
) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}
    for ranked_hits in (lexical_hits[:rank_window_size], vector_hits[:rank_window_size]):
        for rank, hit in enumerate(ranked_hits, start=1):
            document_id = str(hit.get("_id", f"result-{len(merged)}"))
            merged.setdefault(document_id, {**hit, "_score": 0.0})
            merged[document_id]["_score"] += 1.0 / (rank_constant + rank)
    results = sorted(merged.values(), key=lambda hit: hit["_score"], reverse=True)
    for hit in results:
        hit["_score"] = round(hit["_score"], 6)
    return results


def threat_specialist_node(state: AgentMeshState) -> AgentMeshState:
    started_at = _record_agent_started(state, "threat_specialist")
    payload = state.get("search_payload")
    if payload is None:
        raise ValueError("Supervisor did not provide a SearchPayload")

    client = build_elasticsearch_client()
    model = build_embedding_client()
    filter_clauses = [{"term": {field: value}} for field, value in payload["filters"].items()]
    standard_query: Dict[str, Any] = {
        "multi_match": {
            "query": " ".join(payload["target_keywords"]),
            "fields": ["log_message^5", "user_id^4", "target_resource^3", "host^2", "service^2", "severity"],
            "type": "best_fields",
            "operator": "or",
        }
    }
    if filter_clauses:
        standard_query = {"bool": {"must": [standard_query], "filter": filter_clauses}}

    source_fields = [
        "timestamp",
        "severity",
        "service",
        "host",
        "source_ip",
        "user_id",
        "target_resource",
        "status_code",
        "log_message",
        "trace_id",
    ]
    knn_filter: Dict[str, Any] = {"bool": {"filter": filter_clauses}} if filter_clauses else {"match_all": {}}
    knn_query = {
        "field": "vector_embeddings",
        "query_vector": model.embed_query(payload["semantic_intent"]),
        "k": payload["rank_window_size"],
        "num_candidates": max(payload["rank_window_size"] * 2, 100),
        "filter": knn_filter,
    }
    native_query = {
        "size": payload["top_k"],
        "_source": source_fields,
        "retriever": {
            "rrf": {
                "retrievers": [
                    {"standard": {"query": standard_query}},
                    {"knn": knn_query},
                ],
                "rank_window_size": payload["rank_window_size"],
                "rank_constant": 60,
            }
        },
    }

    try:
        response = client.search(index=INDEX_NAME, body=native_query)
        hits = response.get("hits", {}).get("hits", [])
        search_trace = "Native Elasticsearch RRF merged the keyword and semantic security evidence."
    except AuthorizationException as exc:
        if "reciprocal rank fusion (rrf)" not in str(exc).casefold():
            raise
        lexical_response = client.search(
            index=INDEX_NAME,
            body={"query": standard_query, "size": payload["rank_window_size"], "_source": source_fields},
        )
        vector_response = client.search(
            index=INDEX_NAME,
            body={"knn": knn_query, "size": payload["rank_window_size"], "_source": source_fields},
        )
        hits = _merge_ranked_lists(
            lexical_response.get("hits", {}).get("hits", []),
            vector_response.get("hits", {}).get("hits", []),
            payload["rank_window_size"],
        )[: payload["top_k"]]
        search_trace = "The local Elasticsearch license does not permit native RRF; the equivalent rank merge was applied locally."

    state["raw_search_results"] = hits
    for hit in hits:
        source = hit.get("_source", {})
        source["message"] = source.get("log_message", "")
        source["level"] = source.get("severity", "INFO")
        source["node"] = source.get("host", "")
    state["trace"].append(search_trace)

    _record_agent_completed(state, "threat_specialist", started_at, len(hits))
    return state


def compliance_specialist_node(state: AgentMeshState) -> AgentMeshState:
    started_at = _record_agent_started(state, "compliance_specialist")
    payload = state.get("analytics_payload")
    if payload is None:
        raise ValueError("Supervisor did not provide an AnalyticsPayload")

    client = build_elasticsearch_client()
    if payload["metric_type"] == "cluster_health":
        server_info = client.info()
        if server_info.get("version", {}).get("build_flavor") == "serverless":
            index_available = bool(client.indices.exists(index=INDEX_NAME))
            document_count = int(client.count(index=INDEX_NAME).get("count", 0)) if index_available else 0
            health = {
                "status": "available" if index_available else "degraded",
                "service_type": "serverless",
                "version": server_info.get("version", {}).get("number", "unknown"),
                "index_name": INDEX_NAME,
                "index_available": index_available,
                "document_count": document_count,
            }
        else:
            health = dict(client.cluster.health())
        state["raw_cluster_health"] = health
        state["raw_analytics_results"] = {"cluster_health": health}
        state["trace"].append("Compliance Specialist checked platform availability and data health.")
        _record_agent_completed(state, "compliance_specialist", started_at, 1)
        return state

    allowed_fields = {"service", "severity", "host", "status_code", "source_ip", "target_resource"}
    aggregation_field = payload["aggregation_field"]
    if aggregation_field not in allowed_fields:
        raise ValueError(f"Unsupported security aggregation field: {aggregation_field}")

    filter_clauses = [{"term": {field: value}} for field, value in payload["filters"].items()]
    aggregation_query: Dict[str, Any] = {
        "size": 0,
        "query": {"bool": {"filter": filter_clauses}},
        "aggs": {
            "counts_by_field": {"terms": {"field": aggregation_field, "size": payload["bucket_size"]}},
            "events_by_severity": {"terms": {"field": "severity", "size": payload["bucket_size"]}},
            "error_counts_by_service": {
                "filter": {"term": {"severity": "ERROR"}},
                "aggs": {"services": {"terms": {"field": "service", "size": payload["bucket_size"]}}},
            },
        },
    }
    response = client.search(index=INDEX_NAME, body=aggregation_query)
    state["raw_analytics_results"] = response.get("aggregations", {})
    state["trace"].append("Compliance Specialist calculated security-event statistics in Elasticsearch.")
    _record_agent_completed(
        state,
        "compliance_specialist",
        started_at,
        len(response.get("aggregations", {})),
    )
    return state
def _identity_from_query(query: str) -> str | None:
    match = re.search(
        r"\b(?:related\s+to|for|about)\s+(?:(?:user(?:\s+id)?|account)\s+)?['\"]?([a-z0-9._@-]+)"
        r"|\b(?:user(?:\s+id)?|account)\s+['\"]?([a-z0-9._@-]+)",
        query,
        flags=re.IGNORECASE,
    )
    if not match:
        return None
    identity = match.group(1) or match.group(2)
    return identity.strip("'\".,?!")


def _write_security_report(state: AgentMeshState) -> str:
    query = state["user_query"]
    results = state.get("raw_search_results", [])
    requested_user = _identity_from_query(query)
    if requested_user:
        results = [
            hit
            for hit in results
            if requested_user.casefold()
            in f"{hit.get('_source', {}).get('user_id', '')} {hit.get('_source', {}).get('log_message', '')}".casefold()
        ]

    if not results:
        subject = f" for User ID '{requested_user}'" if requested_user else " matching this request"
        return (
            "INCIDENT REPORT SUMMARY:\n"
            f"No matching security records were found{subject}. The available indexed data is insufficient to assess this request.\n\n"
            "Recommended Action: Confirm the relevant security logs have been ingested, then review the request again."
        )

    availability_records = []
    for hit in results:
        source = hit.get("_source", {})
        try:
            status_code = int(source.get("status_code", 0) or 0)
        except (TypeError, ValueError):
            status_code = 0
        message = source.get("log_message", "")
        if status_code >= 500 or re.search(r"timed?\s*out|timeout|upstream.*(?:fail|unavailable)", message, re.IGNORECASE):
            availability_records.append((source, status_code))

    if availability_records:
        availability_summaries = []
        availability_systems = list(
            dict.fromkeys(
                source.get("target_resource") or source.get("host")
                for source, _ in availability_records
                if source.get("target_resource") or source.get("host")
            )
        )
        availability_context = (
            f" The affected resource was {', '.join(availability_systems)}." if availability_systems else ""
        )
        for source, status_code in availability_records[:5]:
            service = source.get("service")
            if status_code == 504 or "gateway" in str(service or "").casefold():
                summary = "A gateway request timed out"
            elif status_code >= 500:
                summary = "A server-side request failed"
            else:
                summary = "A request timed out or its upstream service was unavailable"
            if status_code:
                summary += f" (HTTP {status_code})"
            if service:
                summary += f" for service '{service}'"
            summary += "."
            availability_summaries.append(summary)

        evidence_statement = (
            "This record identifies a request failure but does not establish the underlying cause."
            if len(availability_records) == 1
            else "These records identify request failures but do not establish the underlying cause."
        )
        return (
            "INCIDENT REPORT SUMMARY:\n"
            f"{len(availability_records)} availability-related record(s) were found. "
            f"{' '.join(dict.fromkeys(availability_summaries))}{availability_context} "
            f"{evidence_statement}\n\n"
            "Recommended Action: Check gateway and upstream service health, review request traces and latency, "
            "and determine whether the timeout is recurring."
        )

    authentication_records = [
        hit
        for hit in results
        if re.search(r"auth|ssh|login|credential|sign[ -]?in|access denied", hit.get("_source", {}).get("log_message", ""), re.IGNORECASE)
    ]
    evidence = authentication_records or results
    systems = list(
        dict.fromkeys(
            hit.get("_source", {}).get("target_resource") or hit.get("_source", {}).get("host")
            for hit in evidence
            if hit.get("_source", {}).get("target_resource") or hit.get("_source", {}).get("host")
        )
    )
    event_summaries = []
    for hit in evidence[:5]:
        message = hit.get("_source", {}).get("log_message", "")
        identity = hit.get("_source", {}).get("user_id")
        attempts_match = re.search(r"(\d+)\s+rapid\s+SSH", message, re.IGNORECASE)
        if attempts_match:
            event_summaries.append(
                f"User ID '{identity or requested_user or 'unidentified'}' generated {attempts_match.group(1)} rapid SSH authentication attempts."
            )
        elif identity and re.search(r"auth|ssh|login|credential|sign[ -]?in", message, re.IGNORECASE):
            event_summaries.append(f"Authentication-related activity was recorded for User ID '{identity}'.")

    user_context = f" for User ID '{requested_user}'" if requested_user else ""
    system_context = f" The affected resource was {', '.join(systems)}." if systems else ""
    if event_summaries:
        finding = " ".join(dict.fromkeys(event_summaries)) + system_context
    else:
        finding = f"The review identified {len(evidence)} relevant security record(s){user_context}.{system_context}"

    return (
        "INCIDENT REPORT SUMMARY:\n"
        f"Our security audit identified activity that warrants review{user_context}. {finding} "
        "The records alone do not establish whether the activity was authorized.\n\n"
        "Recommended Action: Verify the activity with the account owner. If unauthorized, suspend the associated credentials and verify the affected host."
    )


def writer_node(state: AgentMeshState) -> AgentMeshState:
    started_at = _record_agent_started(state, "writer")
    intent = state["intent"]
    if intent == "search":
        results = state.get("raw_search_results", [])
        report = _write_security_report(state)
        report_type: Literal["security_incident", "security_analytics", "platform_health"] = "security_incident"
    elif state.get("analytics_payload", {}).get("metric_type") == "cluster_health":
        health = state.get("raw_cluster_health", {})
        if health.get("service_type") == "serverless":
            is_healthy = health.get("status") == "available" and health.get("index_available", False)
            report = (
                "PLATFORM HEALTH SUMMARY:\n"
                f"The Elasticsearch Serverless endpoint is {'available' if is_healthy else 'reporting conditions that need review'}. "
                f"Log index '{health.get('index_name', INDEX_NAME)}' contains {health.get('document_count', 0)} record(s).\n\n"
                f"Recommended Action: {'No immediate action is indicated.' if is_healthy else 'Review endpoint access and log index availability.'}"
            )
        else:
            is_healthy = health.get("status") == "green" and health.get("unassigned_shards", 0) == 0
            report = (
                "PLATFORM HEALTH SUMMARY:\n"
                f"The security log platform is {'operating normally' if is_healthy else 'reporting conditions that need review'}. "
                f"The latest check covered {health.get('number_of_nodes', 'an unknown number of')} host(s).\n\n"
                f"Recommended Action: {'No immediate action is indicated.' if is_healthy else 'Review service availability and audit data continuity.'}"
            )
        results = []
        report_type = "platform_health"
    else:
        analytics = state.get("raw_analytics_results", {})
        error_counts = analytics.get("error_counts_by_service", {})
        buckets = error_counts.get("services", {}).get("buckets", [])
        total = int(error_counts.get("doc_count", 0))
        if total:
            service_lines = "\n".join(f"{bucket['key']}: {bucket['doc_count']}" for bucket in buckets)
            report = (
                "SECURITY OPERATIONS SUMMARY:\n"
                f"{total} ERROR record(s) were found across {len(buckets)} service(s) in the indexed data.\n"
                f"{service_lines}\n\n"
                "Recommended Action: Review each ERROR record and verify whether it is expected, suspicious, or requires investigation."
            )
        else:
            report = (
                "SECURITY OPERATIONS SUMMARY:\n"
                "No ERROR records were found in the indexed data.\n\n"
                "Recommended Action: Continue monitoring and confirm log ingestion is current."
            )
        results = []
        report_type = "security_analytics"

    state["writer_payload"] = WriterPayload(
        report_type=report_type,
        focus=state["user_query"],
        evidence_count=len(results),
    ).model_dump(mode="json")
    state["final_report"] = report
    state["trace"].append("Writer prepared a concise security assessment from the specialist evidence.")
    _record_agent_completed(state, "writer", started_at, len(results))
    return state


def route_after_supervisor(state: AgentMeshState) -> str:
    return "compliance_specialist" if state["intent"] == "analytics" else "threat_specialist"


def build_graph():
    graph = StateGraph(AgentMeshState)
    graph.add_node("supervisor", supervisor_node)
    graph.add_node("threat_specialist", threat_specialist_node)
    graph.add_node("compliance_specialist", compliance_specialist_node)
    graph.add_node("writer", writer_node)

    graph.add_edge(START, "supervisor")
    graph.add_conditional_edges(
        "supervisor",
        route_after_supervisor,
        {
            "threat_specialist": "threat_specialist",
            "compliance_specialist": "compliance_specialist",
        },
    )
    graph.add_edge("threat_specialist", "writer")
    graph.add_edge("compliance_specialist", "writer")
    graph.add_edge("writer", END)
    return graph.compile()


def execute_agent_query(
    user_query: str,
    graph=None,
    context: Dict[str, str] | None = None,
    request_id: str | None = None,
) -> Dict[str, Any]:
    compiled_graph = graph or build_graph()
    initial_state: AgentMeshState = {
        "user_query": user_query,
        "context": context or {},
        "intent": "search",
        "route": "pending",
        "supervisor_payload": {},
        "search_payload": None,
        "analytics_payload": None,
        "writer_payload": {},
        "raw_search_results": [],
        "raw_analytics_results": {},
        "raw_cluster_health": {},
        "final_report": "",
        "trace": [],
        "agent_execution": [],
    }
    result = compiled_graph.invoke(initial_state)
    execution_records = result.get("agent_execution", [])
    selected_agent = result["route"]
    skipped_agent = (
        "compliance_specialist" if selected_agent == "threat_specialist" else "threat_specialist"
        if selected_agent == "compliance_specialist"
        else None
    )
    if skipped_agent:
        supervisor_completed_at = result["supervisor_payload"].get(
            "completed_at", datetime.now(timezone.utc).isoformat()
        )
        execution_records.append(
            {
                "agent": skipped_agent,
                "status": "skipped",
                "started_at": supervisor_completed_at,
                "completed_at": supervisor_completed_at,
                "duration_ms": 0,
                "result_count": 0,
            }
        )
    return {
        "request_id": request_id,
        "intent": result["intent"],
        "route": result["route"],
        "supervisor_payload": result["supervisor_payload"],
        "search_payload": result.get("search_payload"),
        "analytics_payload": result.get("analytics_payload"),
        "writer_payload": result["writer_payload"],
        "search_results": result["raw_search_results"],
        "analytics": result["raw_analytics_results"],
        "cluster_health": result["raw_cluster_health"],
        "final_report": result["final_report"],
        "trace": result["trace"],
        "agent_execution": execution_records,
    }