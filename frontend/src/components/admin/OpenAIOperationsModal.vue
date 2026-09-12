<template>
  <BaseDialog :show="show" :title="t('admin.openaiOperations.title')" width="wide" @close="$emit('close')">
    <div class="min-w-0 space-y-4 text-sm">
      <div class="flex flex-wrap items-center gap-2 border-b border-gray-200 pb-3 dark:border-dark-600">
        <div role="tablist" class="flex min-w-0 flex-wrap gap-1">
          <button v-for="view in tabs" :key="view" type="button" role="tab" class="btn btn-sm"
            :class="tab === view ? 'btn-primary' : 'btn-secondary'" :aria-selected="tab === view" @click="tab = view">
            {{ t(`admin.openaiOperations.${view}`) }}
          </button>
        </div>
        <button type="button" class="btn btn-secondary ml-auto" :title="t('common.refresh')" :aria-label="t('common.refresh')" :disabled="loading || saving" @click="loadData">
          <Icon name="refresh" size="sm" :class="{ 'animate-spin': loading }" />
        </button>
      </div>
      <p v-if="error" role="alert" class="text-red-600">{{ error }}</p>
      <div v-if="loading && !settings" role="status">{{ t('common.loading') }}</div>
      <form v-else-if="tab === 'settings' && settings" class="space-y-5" @submit.prevent="save">
        <fieldset :disabled="saving || loading" class="space-y-4">
          <label class="flex items-center gap-2">
            <input v-model="settings.recovery.enabled" type="checkbox" data-testid="recovery-enabled" />
            {{ t('admin.openaiOperations.recoveryEnabled') }}
          </label>
          <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <label v-for="field in recoveryFields" :key="field.key">
              {{ t(`admin.openaiOperations.${field.key}`) }}
              <input v-model.number="settings.recovery[field.key]" type="number" class="input mt-1" required :min="field.min" :max="field.max" />
            </label>
          </div>
          <h3 class="border-t border-gray-200 pt-4 font-medium dark:border-dark-600">{{ t('admin.openaiOperations.reasoning') }}</h3>
          <div class="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <label v-for="field in reasoningFields" :key="field.key">
              {{ t(`admin.openaiOperations.${field.key}`) }}
              <input v-model.number="settings.reasoning[field.key]" type="number" class="input mt-1" required :min="field.min" :max="field.max" />
            </label>
          </div>
          <label class="flex items-center gap-2 border-t border-gray-200 pt-4 dark:border-dark-600">
            <input type="checkbox" :checked="settings.new_account_defaults !== null" data-testid="template-enabled" @change="toggleTemplate" />
            {{ t('admin.openaiOperations.template') }}
          </label>
          <div v-if="settings.new_account_defaults" class="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <label>{{ t('admin.openaiOperations.proxy') }}
              <select v-model="settings.new_account_defaults.proxy_id" class="input mt-1">
                <option :value="null">{{ t('admin.openaiOperations.unset') }}</option>
                <option :value="0">{{ t('admin.openaiOperations.direct') }}</option>
                <option v-for="proxy in proxies" :key="proxy.id" :value="proxy.id">{{ proxy.name }}</option>
                <option v-if="settings.new_account_defaults.proxy_id && !proxies.some(p => p.id === settings!.new_account_defaults!.proxy_id)" :value="settings.new_account_defaults.proxy_id">#{{ settings.new_account_defaults.proxy_id }}</option>
              </select>
            </label>
            <label>{{ t('admin.openaiOperations.tlsEnabled') }}
              <select v-model="settings.new_account_defaults.enable_tls_fingerprint" class="input mt-1" data-testid="template-tls">
                <option :value="null">{{ t('admin.openaiOperations.unset') }}</option>
                <option :value="true">{{ t('common.enabled') }}</option>
                <option :value="false">{{ t('common.disabled') }}</option>
              </select>
            </label>
            <label>{{ t('admin.openaiOperations.profile') }}
              <select v-model="settings.new_account_defaults.tls_fingerprint_profile_id" class="input mt-1">
                <option :value="null">{{ t('admin.openaiOperations.unset') }}</option>
                <option :value="0">{{ t('admin.openaiOperations.platformDefault') }}</option>
                <option :value="-1">{{ t('admin.openaiOperations.stableRandom') }}</option>
                <option v-for="profile in profiles" :key="profile.id" :value="profile.id">{{ profile.name }}</option>
                <option v-if="settings.new_account_defaults.tls_fingerprint_profile_id && settings.new_account_defaults.tls_fingerprint_profile_id > 0 && !profiles.some(p => p.id === settings!.new_account_defaults!.tls_fingerprint_profile_id)" :value="settings.new_account_defaults.tls_fingerprint_profile_id">#{{ settings.new_account_defaults.tls_fingerprint_profile_id }}</option>
              </select>
            </label>
            <label>{{ t('admin.openaiOperations.fingerprintMode') }}
              <select v-model="settings.new_account_defaults.codex_fingerprint_mode" class="input mt-1">
                <option :value="null">{{ t('admin.openaiOperations.unset') }}</option>
                <option v-for="mode in ['off', 'device', 'session', 'full', 'machine']" :key="mode" :value="mode">{{ mode }}</option>
              </select>
            </label>
            <label>{{ t('admin.openaiOperations.concurrency') }}
              <input :value="settings.new_account_defaults.concurrency ?? ''" type="number" min="1" max="1000" class="input mt-1"
                :placeholder="t('admin.openaiOperations.unset')" @input="setConcurrency" />
            </label>
          </div>
          <div class="flex justify-end">
            <button type="submit" class="btn btn-primary" :disabled="saving || loading">{{ t('common.save') }}</button>
          </div>
        </fieldset>
      </form>
      <template v-else-if="tab === 'pool'">
        <label class="block max-w-sm">{{ t('admin.openaiOperations.group') }}
          <select v-model.number="groupID" class="input mt-1" :disabled="loading" @change="loadData">
            <option :value="0">{{ t('admin.openaiOperations.all') }}</option>
            <option v-for="group in groups" :key="group.id" :value="group.id">{{ group.name }}</option>
          </select>
        </label>
        <dl v-if="pool" class="flex flex-wrap gap-x-6 gap-y-2 border-y border-gray-200 py-3 dark:border-dark-600">
          <div v-for="key in ['total', 'schedulable', 'cooling', 'error'] as const" :key="key">
            <dt class="text-gray-500">{{ t(`admin.openaiOperations.${key}`) }}</dt><dd class="font-semibold">{{ pool[key] }}</dd>
          </div>
        </dl>
        <div class="max-h-[50vh] overflow-auto">
          <table class="w-full text-left"><thead><tr>
            <th>{{ t('admin.openaiOperations.account') }}</th><th>{{ t('admin.openaiOperations.status') }}</th>
            <th>{{ t('admin.openaiOperations.cooldown') }}</th><th>{{ t('admin.openaiOperations.escape') }}</th>
          </tr></thead><tbody>
            <tr v-for="account in pool?.accounts" :key="account.account_id">
              <td class="max-w-48 break-words">#{{ account.account_id }} {{ account.name }}</td>
              <td>{{ account.status }}<span v-if="account.tls_proxy_fallback" class="block text-amber-600">{{ t('admin.openaiOperations.proxyFallback') }}</span></td>
              <td><div v-for="cooldown in account.cooldowns.filter(c => new Date(c.until).getTime() > now.getTime())" :key="cooldown.reason + cooldown.until">
                {{ cooldown.reason }} · {{ formatDateTime(cooldown.until) }}
              </div></td>
              <td>{{ account.sticky_escape_reason || '-' }}</td>
            </tr>
          </tbody></table>
          <p v-if="pool && !pool.accounts.length" class="py-4 text-gray-500">{{ t('admin.openaiOperations.empty') }}</p>
        </div>
        <p v-if="pool" class="text-xs text-gray-500">{{ t('admin.openaiOperations.observedAt') }} {{ formatDateTime(pool.observed_at) }}</p>
      </template>
      <template v-else-if="tab === 'reasoning' || tab === 'recovery'">
        <form class="flex flex-wrap items-end gap-2" @submit.prevent="loadData">
          <label>{{ t('admin.openaiOperations.accountID') }}
            <input v-model.number="accountID" type="number" min="0" required class="input mt-1 max-w-48" />
          </label>
          <button type="submit" class="btn btn-secondary" :disabled="loading">{{ t('admin.openaiOperations.query') }}</button>
        </form>
        <div class="max-h-[50vh] overflow-auto">
          <table v-if="tab === 'reasoning'" class="w-full text-left"><thead><tr>
            <th>{{ t('admin.openaiOperations.model') }}</th><th>{{ t('admin.openaiOperations.tokens') }}</th>
            <th>{{ t('admin.openaiOperations.hits') }}</th><th>{{ t('admin.openaiOperations.signal') }}</th>
          </tr></thead><tbody>
            <tr v-for="bucket in buckets" :key="bucket.model + ':' + bucket.reasoning_tokens">
              <td class="max-w-56 break-words">{{ bucket.model }}</td><td>{{ bucket.reasoning_tokens }}</td><td>{{ bucket.hits }}</td>
              <td :class="{ 'text-amber-600': bucket.suspected_truncation }">{{ bucket.suspected_truncation ? t('admin.openaiOperations.suspected') : '-' }}</td>
            </tr>
          </tbody></table>
          <template v-else>
            <table class="mb-5 w-full text-left"><thead><tr>
              <th>{{ t('admin.openaiOperations.account') }}</th><th>{{ t('admin.openaiOperations.attempts') }}</th>
              <th>{{ t('admin.openaiOperations.failures') }}</th><th>{{ t('admin.openaiOperations.nextAttempt') }}</th>
            </tr></thead><tbody><tr v-for="record in records" :key="record.account_id">
              <td>#{{ record.account_id }}</td><td>{{ record.attempts }}</td><td>{{ record.consecutive_failures }}</td>
              <td>{{ record.permanent ? t('admin.openaiOperations.permanent') : formatDateTime(record.next_attempt_at) }}</td>
            </tr></tbody></table>
            <table class="w-full text-left"><thead><tr>
              <th>{{ t('admin.openaiOperations.time') }}</th><th>{{ t('admin.openaiOperations.account') }}</th>
              <th>{{ t('admin.openaiOperations.classification') }}</th><th>{{ t('admin.openaiOperations.action') }}</th><th>{{ t('admin.openaiOperations.outcome') }}</th>
            </tr></thead><tbody><tr v-for="event in events" :key="event.id">
              <td>{{ formatDateTime(event.created_at) }}</td><td>#{{ event.account_id }} · {{ event.attempt }}</td>
              <td>{{ event.classification }}</td><td>{{ event.action }}</td><td>{{ event.outcome }}</td>
            </tr></tbody></table>
          </template>
          <p v-if="tab === 'reasoning' ? !buckets.length : !events.length" class="py-4 text-gray-500">{{ t('admin.openaiOperations.empty') }}</p>
        </div>
      </template>
    </div>
  </BaseDialog>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useNow } from '@vueuse/core'
import { useI18n } from 'vue-i18n'
import BaseDialog from '@/components/common/BaseDialog.vue'
import Icon from '@/components/icons/Icon.vue'
import { openaiOperationsAPI as api, type OpenAIOperationsSettings, type AccountPoolState, type ReasoningBucket, type RecoveryEvent } from '@/api/admin/openaiOperations'
import { tlsFingerprintProfileAPI } from '@/api/admin/tlsFingerprintProfile'
import { formatDateTime } from '@/utils/format'
import { useAppStore } from '@/stores/app'

const props = withDefaults(defineProps<{ show: boolean; groups?: { id: number; name: string }[]; proxies?: { id: number; name: string }[] }>(), { groups: () => [], proxies: () => [] })
defineEmits<{ close: [] }>()
const { t } = useI18n()
const app = useAppStore()
const tabs = ['pool', 'reasoning', 'recovery', 'settings'] as const
const tab = ref<typeof tabs[number]>('pool')
const settings = ref<OpenAIOperationsSettings | null>(null)
const profiles = ref<{ id: number; name: string }[]>([])
const pool = ref<AccountPoolState | null>(null)
const buckets = ref<ReasoningBucket[]>([])
const events = ref<RecoveryEvent[]>([])
const accountID = ref(0)
const groupID = ref(0)
const loading = ref(false)
const saving = ref(false)
const error = ref('')
const now = useNow({ interval: 1000 })
const records = computed(() => (pool.value?.recovery ?? []).filter(r => !accountID.value || r.account_id === accountID.value))
const recoveryFields = [
  { key: 'interval_minutes', min: 5, max: 1440 }, { key: 'failure_threshold', min: 1, max: 100 },
  { key: 'backoff_minutes', min: 5, max: 10080 }, { key: 'cooldown_minutes', min: 1, max: 1440 }
] as const
const reasoningFields = [
  { key: 'window_hours', min: 1, max: 168 }, { key: 'sample_limit', min: 2, max: 10000 }, { key: 'threshold', min: 2, max: 10000 }
] as const
let generation = 0
let refreshTimer: ReturnType<typeof setInterval> | undefined

function toggleTemplate() {
  if (!settings.value) return
  settings.value.new_account_defaults = settings.value.new_account_defaults ? null : {
    proxy_id: null, enable_tls_fingerprint: null, tls_fingerprint_profile_id: null, codex_fingerprint_mode: null, concurrency: null
  }
}
function setConcurrency(event: Event) {
  const value = (event.target as HTMLInputElement).value
  if (settings.value?.new_account_defaults) settings.value.new_account_defaults.concurrency = value === '' ? null : Number(value)
}
async function load(includeSettings = true) {
  const id = ++generation
  loading.value = true
  error.value = ''
  try {
    const [nextPool, nextBuckets, nextEvents, nextSettings, nextProfiles] = await Promise.all([
      api.pool(groupID.value), api.reasoning(accountID.value), api.events(accountID.value),
      includeSettings ? api.getSettings() : Promise.resolve(null),
      includeSettings ? tlsFingerprintProfileAPI.list() : Promise.resolve(null)
    ])
    if (id !== generation || !props.show) return
    pool.value = nextPool
    buckets.value = nextBuckets
    events.value = nextEvents
    if (nextSettings) settings.value = nextSettings
    if (nextProfiles) profiles.value = nextProfiles
  } catch {
    if (id === generation) error.value = t('admin.openaiOperations.loadFailed')
  } finally {
    if (id === generation) loading.value = false
  }
}
function loadData() { return load(false) }
async function save() {
  if (!settings.value || saving.value || loading.value) return
  const id = generation
  saving.value = true
  try {
    const saved = await api.setSettings(JSON.parse(JSON.stringify(settings.value)))
    if (id !== generation || !props.show) return
    settings.value = saved
    app.showSuccess(t('common.saved'))
    await loadData()
  } catch {
    if (id === generation) error.value = t('admin.openaiOperations.saveFailed')
  } finally {
    saving.value = false
  }
}
watch(() => props.show, show => {
  generation++
  clearInterval(refreshTimer)
  if (show) {
    settings.value = null
    pool.value = null
    buckets.value = []
    events.value = []
    void load()
    refreshTimer = setInterval(() => { if (!loading.value && !saving.value && tab.value !== 'settings') void loadData() }, 15000)
  }
}, { immediate: true })
onBeforeUnmount(() => { generation++; clearInterval(refreshTimer) })
</script>

<style scoped>
th, td { padding: 0.625rem; vertical-align: top; border-bottom: 1px solid rgb(156 163 175 / 20%); }
th { font-weight: 500; white-space: nowrap; }
</style>
