export default {
  openaiOperations: {
    title: 'OpenAI Operations', pool: 'Account Pool', reasoning: 'Reasoning', recovery: 'Recovery', settings: 'Settings',
    recoveryEnabled: 'Enable OAuth recovery for error accounts', interval_minutes: 'Interval (minutes)',
    failure_threshold: 'Consecutive failure threshold', backoff_minutes: 'Failure backoff (minutes)', cooldown_minutes: '429 cooldown (minutes)',
    window_hours: 'Observation window (hours)', sample_limit: 'Recent xhigh request limit', threshold: 'Equal-value cluster threshold',
    template: 'New OpenAI account defaults', proxy: 'Proxy', direct: 'Direct', tlsEnabled: 'TLS fingerprint',
    profile: 'TLS profile', platformDefault: 'Platform default', stableRandom: 'Stable per-account assignment',
    fingerprintMode: 'codex_fingerprint_mode', concurrency: 'Concurrency', unset: 'Keep imported value',
    group: 'Group', all: 'All', total: 'Total', schedulable: 'Schedulable', cooling: 'Cooling', error: 'Error',
    account: 'Account', status: 'Status', cooldown: 'Cooldown / recovery time', escape: 'Sticky escape condition',
    proxyFallback: 'HTTPS proxy: TLS profile inactive', empty: 'No data', observedAt: 'Snapshot:',
    accountID: 'Account ID (0 for all)', query: 'Query', model: 'Response model', tokens: 'Reasoning tokens',
    hits: 'Hits', signal: 'Cluster signal', suspected: 'Suspected reasoning truncation',
    attempts: 'Inspections', failures: 'Consecutive failures', nextAttempt: 'Next inspection', permanent: 'Reauthorization required',
    time: 'Time', classification: 'Classification', action: 'Action', outcome: 'Outcome',
    loadFailed: 'Unable to load operations data. Retry.', saveFailed: 'Save failed. Check configuration bounds and retry.'
  }
}
