export default {
  openaiOperations: {
    title: 'OpenAI 运维', pool: '账号池', reasoning: '推理观测', recovery: '巡检记录', settings: '运维设置',
    recoveryEnabled: '启用 error 账号 OAuth 巡检', interval_minutes: '巡检间隔（分钟）',
    failure_threshold: '连续失败阈值', backoff_minutes: '失败退避（分钟）', cooldown_minutes: '429 冷却（分钟）',
    window_hours: '观测窗口（小时）', sample_limit: '最近 xhigh 请求数上限', threshold: '同值聚集阈值',
    template: '新 OpenAI 账号默认模板', proxy: '代理', direct: '直连', tlsEnabled: 'TLS 指纹',
    profile: 'TLS 画像', platformDefault: '平台默认', stableRandom: '按账号稳定分配',
    fingerprintMode: 'codex_fingerprint_mode', concurrency: '并发上限', unset: '不覆盖导入值',
    group: '分组', all: '全部', total: '账号总数', schedulable: '可调度', cooling: '冷却中', error: 'Error',
    account: '账号', status: '状态', cooldown: '冷却原因 / 恢复时间', escape: '粘性逃逸条件',
    proxyFallback: 'HTTPS 代理：TLS 画像未生效', empty: '暂无数据', observedAt: '快照时间：',
    accountID: '账号 ID（0 为全部）', query: '查询', model: '响应模型', tokens: '推理 token',
    hits: '命中次数', signal: '聚集信号', suspected: '疑似推理截断',
    attempts: '巡检次数', failures: '连续失败', nextAttempt: '下次巡检', permanent: '待重新授权',
    time: '时间', classification: '分类', action: '动作', outcome: '结果',
    loadFailed: '运维数据加载失败，请重试', saveFailed: '保存失败，请检查配置范围并重试'
  }
}
