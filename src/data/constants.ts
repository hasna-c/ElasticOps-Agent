export const PRESET_INQUIRIES = [
  {
    id: 'cluster_health',
    label: 'Cluster health',
    query: 'Summarize the current Elasticsearch cluster health',
  },
  {
    id: 'search',
    label: 'Find recent errors',
    query: 'Find recent gateway errors and timeouts',
  },
  {
    id: 'analytics',
    label: 'Summarize error trends',
    query: 'Summarize error counts by service',
  },
  {
    id: 'failed_access_audits',
    label: 'Failed Access Audits',
    query: 'Show failed access audits and authentication attempts',
  },
  {
    id: 'bucket_policy_changes',
    label: 'Bucket Policy Changes',
    query: 'Find bucket access policy changes that may expose data publicly',
  },
] as const;