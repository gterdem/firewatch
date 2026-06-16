/**
 * WebhookField — webhook_url + alert_on_sync controls (ADR-0059 D4 / issue #661).
 *
 * Preserves the webhook_url_set honest-signal + SecretStr masked-state behaviour
 * from LocalAiPanel (ADR-0006): the server never returns the secret value; GET returns
 * null when set; webhook_url_set=true means a URL IS configured. The UI shows a
 * "•••• set — type to replace" placeholder when the server reports it is set.
 * The secret is NEVER echoed back to the DOM in plaintext.
 *
 * alert_on_sync: persisted via PUT on toggle.
 *
 * Moved from LocalAiPanel "Alerting" section group (issue #661).
 */

import { Button } from '../ds'

const LABEL_STYLE: React.CSSProperties = {
  display: 'block',
  fontSize: 'var(--fw-fs-sm)',
  color: 'var(--fw-t2)',
  marginBottom: 4,
  fontWeight: 'var(--fw-fw-medium)',
  fontFamily: 'var(--fw-font-ui)',
}

const HELP_STYLE: React.CSSProperties = {
  fontSize: 'var(--fw-fs-sm)',
  color: 'var(--fw-t3)',
  fontFamily: 'var(--fw-font-ui)',
  marginTop: 4,
}

interface WebhookFieldProps {
  /** Live text-field value (controlled). Empty = user has not typed anything. */
  webhookUrl: string
  onWebhookUrlChange: (e: React.ChangeEvent<HTMLInputElement>) => void
  onSaveWebhook: () => void
  /** True when the server has a webhook_url set (honest signal, ADR-0006 / #494). */
  webhookIsSet: boolean
  /** alert_on_sync field value. */
  alertOnSync: boolean
  onAlertOnSyncChange: (e: React.ChangeEvent<HTMLInputElement>) => void
  disabled?: boolean
}

export function WebhookField({
  webhookUrl,
  onWebhookUrlChange,
  onSaveWebhook,
  webhookIsSet,
  alertOnSync,
  onAlertOnSyncChange,
  disabled = false,
}: WebhookFieldProps) {
  return (
    <>
      {/* Webhook URL — SecretStr on server; placeholder reflects configured state */}
      <div style={{ marginBottom: 14 }}>
        <label htmlFor="webhook-url" style={LABEL_STYLE}>
          Webhook URL
        </label>
        <div style={{ display: 'flex', gap: 8 }}>
          <input
            id="webhook-url"
            type="url"
            value={webhookUrl}
            onChange={onWebhookUrlChange}
            placeholder={
              webhookIsSet ? '•••• set — type to replace' : 'https://hooks.slack.com/...'
            }
            data-testid="webhook-url-input"
            disabled={disabled}
            style={{
              flex: 1,
              padding: '8px 12px',
              background: 'var(--fw-bg-input)',
              border: '1px solid var(--fw-border-l)',
              borderRadius: 'var(--fw-r-sm)',
              color: 'var(--fw-t1)',
              fontSize: 'var(--fw-fs-body)',
              fontFamily: 'var(--fw-font-mono)',
              outline: 'none',
            }}
          />
          <Button
            variant="primary"
            size="sm"
            onClick={onSaveWebhook}
            disabled={disabled}
            data-testid="webhook-url-save"
          >
            Save
          </Button>
        </div>
        <div style={HELP_STYLE}>
          Alerts at or above the threshold are posted to this URL.
        </div>
      </div>

      {/* alert_on_sync — "Notify me when a scheduled pull is blocked" */}
      <div style={{ marginBottom: 4 }}>
        <label
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            fontSize: 'var(--fw-fs-sm)',
            color: 'var(--fw-t1)',
            cursor: 'pointer',
            fontFamily: 'var(--fw-font-ui)',
          }}
        >
          <input
            type="checkbox"
            checked={alertOnSync}
            onChange={onAlertOnSyncChange}
            disabled={disabled}
            data-testid="alert-on-sync-blocks"
          />
          Notify me when a scheduled pull is blocked
        </label>
        <div style={{ ...HELP_STYLE, marginLeft: 24 }}>
          Sends an alert via the webhook when an automatic data-pull is throttled or rejected.
        </div>
      </div>
    </>
  )
}
